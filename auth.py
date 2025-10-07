from cryptography.fernet import Fernet
from flask import Blueprint, render_template, request, flash, redirect, url_for, session, current_app
from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import abort
from __init__ import db, limiter
from datetime import datetime, timedelta
from models import User, Comment
from PyCourier import PyCourier
from AuthAlpha import PassHashing, TwoFactorAuth
from dotenv import load_dotenv
from os import environ
from random import sample

load_dotenv()

sender          = environ['SENDER']
password        = environ['PASSWORD']

auth            = Blueprint("auth", __name__, template_folder="templates/auth_templates/")

two_factor_obj  = TwoFactorAuth()
password_police = PassHashing("argon2id")
otp_police      = PassHashing("pbkdf2:sha256")

"""
Decorators:
-> @auth.route : Used to define routes and accepted request methods (POST/GET) for views.
-> @login_required : Used to restrict access to certain views. These views are accessible only when the user
is authenticated.
-> @auth.after_request : Specifies a list of commands that are run after every request.
"""


@auth.after_request
def apply_caching(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Makes sure that back button doesn't take you back to user session after logout.
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

@auth.route('/', methods=['GET'])
@limiter.exempt
def index():
    """
    The Home-Page
    :return: renders template project_index.html
    """
    project_list = (
        "PyCourier",
        "Theorist-Dev",
        "SteelIndustry_DefectCLF",
        "Regression",
        "Waltz",
        "cpp_mysql_wrapper",
        "AuthAlpha",
        "leaf",
        "ML",
        "Encrypt0r",
        "Open-Software-Update"
    )

    projects = sample(project_list, 2)

    return render_template("index.html", projects=projects)


@auth.route('/create', methods=['GET', 'POST'])
@limiter.limit("5/minute;10/hour")
def create():
    """
    Initiates the account creation process,

    1.  (NAME, EMAIL and OTP hash) are stored in the session to persist data between
        requests.

    2.  After that using an instance of SQLALCHEMY() (db), we check if the e-mail id
        (Unique Key) entered by the user already exists. If the checks are passed,
        the user is redirected to auth.otp.

    /* P.S Regex has already been implemented in the 'create.html' and 'otp.html' files. */

    :return: renders template 'create.html', user=current_user
    """
    if request.method == 'POST':
        session['NAME'] = request.form['USERNAME']
        session['EMAIL'] = request.form['EMAIL']
        exists = db.session.query(User.id).filter_by(email=session['EMAIL']).first()
        if not exists:
            session['referred_from_create'] = True
            server_otp = two_factor_obj.static_otp(otp_len=6)

            courier = PyCourier(
                sender_email=sender,
                sender_password=password,
                recipients=[session['EMAIL']],
                message=f"""Theorist-Dev Email Verification Code:
OTP: {server_otp} (Valid for 5 minutes)

If you didn't attempt this registration, you can safely ignore this email, someone might have typed it in by mistake.
""",
                msg_type="plain",
                subject="Theorist-Dev Email Verification"
            )

            courier.send_courier()

            session['SERVER_OTP'] = otp_police.generate_password_hash(server_otp, cost=50000)
            session['OTP_TIMESTAMP'] = datetime.now().isoformat()
            return redirect(url_for('auth.otp'))
        else:
            flash('Email already in use!', category='error')

    return render_template("create.html")


@auth.route('/otp', methods=['GET', 'POST'])
@limiter.limit("20 per day")
def otp():
    """
    Used to perform OTP checks specifically for account creation (i.e. for email verification).

    1.  This page is only accessible if session key 'referred_from_create' is set to True.
        A threat actor cannot modify this data as the sessions are cryptographically signed
        and tamper-proof.

    2.  ('GET' request): A random OTP of length 6 is generated and is e-mailed to the previously
        stored object with session key -> 'EMAIL'.
        This OTP's pbkdf2:sha256 (50,000 rounds) hash is then stored in the session,
        to be used for verification of USER_OTP.

    3.  ('POST' request): A user can make a 'POST' request on this page to submit the OTP sent to
        their e-mail and set a password, the hash of the USER_OTP is checked against the pre-known
        hash of the generated OTP, if the user enters the correct OTP, its hash is deleted from
        session and a new user table entry is made. Password is hashed using argon2id with the help
        of AuthAlpha package.

    4.  The submitted password is never-ever stored without being hashed.

        /*
        P.S OTP hashes exist in the session never for more than 5 minutes.
        */

    5.  Database Entry: A new User object is created which is a class inherited from db.Model
        and UserMixin that stores the Database structure to manage user data. SQLALCHEMY takes
        care of registering a new user entry. The default role of a user is 'user'
        (see User class in models.py). It can be later changed by a user with admin privileges.

    /*  Successful navigation through this view creates an account and logs in the user
        redirecting them to auth.success.
        By default, 'Remember me functionality', is disabled. It can be turned ON by changing
        'remember = True'. */

    NOTE: Turning on 'Remember me' breaks the permanent session time-out functionality. The
    session expiring due to not entering OTP still works.

    :return: renders template 'otp.html'
    """
    if not ('referred_from_create' in session and session['referred_from_create']):
        abort(403)

    if 'EMAIL' not in session:
        abort(403)

    if request.method == 'POST':
        user_otp = request.form['OTP']
        user_password = password_police.generate_password_hash(request.form['PASSWORD'])

        otp_timestamp = datetime.fromisoformat(session.get('OTP_TIMESTAMP', '1970-01-01'))
        if datetime.now() > otp_timestamp + timedelta(minutes=5):
            flash('Your One-Time Password has expired. Please log in again.', category='error')
            return redirect(url_for('auth.create'))

        if otp_police.check_password_hash(session['SERVER_OTP'], user_otp):
            try:
                del session['SERVER_OTP']
                del session['referred_from_create']

                new_user = User(name=session['NAME'],
                                password=user_password,
                                email=session['EMAIL'],
                                active=True,
                                last_confirmed_at=datetime.now())

                db.session.add(new_user)
                db.session.commit()

                session.clear()
                login_user(new_user, remember=False)
                session.permanent = True

                return redirect(url_for('auth.success'))

            except IntegrityError:
                db.session.rollback()
                flash('This email address has just been registered. Please log in.', category='error')
                return redirect(url_for('auth.login'))
        else:
            flash('Wrong otp', category='error')

    return render_template("otp.html")


@auth.route('/success')
@login_required
@limiter.exempt
def success():
    """
    The page where the user is redirected on successful creation of an account.

    :return: renders template 'success.html'
    """
    return render_template("success.html")


@auth.route('/login', methods=['GET', 'POST'])
def login():
    """

    """
    if current_user.is_authenticated:
        return redirect(url_for('auth.secrets'))
    if request.method == 'POST':
        session['EMAIL'] = request.form['EMAIL']
        user_pass = request.form['PASSWORD']

        user = User.query.filter_by(email=session['EMAIL']).first()
        if user and password_police.check_password_hash(user.password, user_pass):
            if user.two_FA:
                session['2FA_TYPE'] = user.two_FA_type

                if user.two_FA_type == "EMAIL":
                    server_otp = two_factor_obj.static_otp(otp_len=6)

                    courier = PyCourier(
                        sender_email=sender,
                        sender_password=password,
                        recipients=[session['EMAIL']],
                        message=f"""\
    Theorist-Dev Email Two Factor Authentication:
    OTP: {server_otp} (Valid for 5 minutes)
    
    If you didn't attempt this login, someone has your account details, change them immediately:
    example.com
                                """,
                        msg_type="plain",
                        subject="Theorist-Dev Email Two Factor Authentication"
                    )

                    courier.send_courier()
                    session['SERVER_OTP'] = otp_police.generate_password_hash(server_otp, cost=50000)
                    session['OTP_TIMESTAMP'] = datetime.now().isoformat()

                return redirect(url_for('auth.mfa_login'))
            else:
                session.clear()
                login_user(user, remember=False)
                user.active = True
                user.last_confirmed_at = datetime.now()
                db.session.commit()
                session.permanent = True
                return redirect(url_for('auth.secrets'))
        else:
            del session['EMAIL']
            flash('Invalid Email or Password', category='error')
            return redirect(url_for('auth.login'))

    return render_template("login.html")


@auth.route('/mfa-login', methods=['GET', 'POST'])
def mfa_login():
    """

    """
    if '2FA_TYPE' not in session:
        abort(403)

    if 'EMAIL' not in session:
        abort(403)

    user = User.query.filter_by(email=session['EMAIL']).first()

    if request.method == 'POST':
        user_otp = request.form['OTP']
        if user and session['2FA_TYPE'] == "EMAIL":
            # check expiry
            otp_timestamp = datetime.fromisoformat(session.get('OTP_TIMESTAMP', '1970-01-01'))
            if datetime.now() > otp_timestamp + timedelta(minutes=5):
                flash('Your One-Time Password has expired. Please log in again.', category='error')
                return redirect(url_for('auth.login'))
            # check otp
            if otp_police.check_password_hash(session['SERVER_OTP'], user_otp):
                session.clear()
                login_user(user, remember=False)
                user.active = True
                user.last_confirmed_at = datetime.now()
                db.session.commit()
                session.permanent = True
                return redirect(url_for('auth.secrets'))
            else:
                flash('Invalid OTP', category='error')

        elif user and session['2FA_TYPE'] == "TOTP":
            try:
                cipher = Fernet(current_app.config["MASTER_TOTP_SECRET_KEY"])
                encrypted_key = user.two_FA_key
                encrypted_key = encrypted_key.encode("utf-8")
                shared_secret = cipher.decrypt(encrypted_key).decode('utf-8')
                if two_factor_obj.verify(str(shared_secret), user_otp):
                    session.clear()
                    login_user(user, remember=False)
                    user.active = True
                    user.last_confirmed_at = datetime.now()
                    db.session.commit()
                    session.permanent = True
                    return redirect(url_for('auth.secrets'))
                else:
                    flash('Incorrect otp, try again.', category='error')
            except ValueError:
                flash('Incorrect otp, try again.', category='error')
        else:
            flash('Invalid OTP', category='error')

    return render_template("mfa-login.html")


@auth.route('/logout')
@login_required
def logout():
    """
    Logs-out (terminates session) of a user already logged-in.
    Will be automatically called after session times-out after 12 hours.

    :return: redirects to 'auth.login'
    """
    user = User.query.get(current_user.id)
    user.active = False
    db.session.commit()

    session.clear()
    logout_user()

    return redirect(url_for('auth.login'))


@auth.route('/secrets', methods=['GET', 'POST'])
@login_required
def secrets():
    """
    Account overview page, gateway to enable 2FA. Users gets to choose between
    EMAIL based 2FA and TOTP based 2FA

    :return: renders template 'secrets.html'
    """
    if request.method == "POST":
        if request.form['submit'] == 'EMAIL-OTP':
            user = User.query.get(current_user.id)
            user.two_FA = True
            user.two_FA_type = "EMAIL"
            db.session.commit()
            flash("2FA enabled!", category="success")
        elif request.form['submit'] == 'TOTP':
            return redirect(url_for("auth.two_fa"))

    return render_template("secrets.html")


@auth.route('/two-FA', methods=['GET', 'POST'])
@login_required
def two_fa():
    """
    Accessible iff 'referred_from_secrets_for_TOTP' session key is set to True.
    [I] 'GET' Request: A TOTP secret and its corresponding QR code is generated,
        Any refresh/ wrong OTP or password POST changes the TOTP tokens.

    [II] 'POST' Request: Using an authenticator app, the user enters their OTP and password
        If the OTP and password are correct, user.2FA is flipped to True and the TOTP token
        is encrypted with the user's password which is then stored in db.

    :return: renders template 'two-FA.html'
    """
    if request.method == 'GET':
        secret = two_factor_obj.totp(user_name=current_user.email, issuer_name="theorist-dev.com")

    if request.method == 'POST':
        token = request.form['SECRET']
        USER_OTP = request.form['OTP']
        PASSWORD = request.form['PASSWORD']
        user = User.query.filter_by(email=current_user.email).first()

        if two_factor_obj.verify(token, USER_OTP) and password_police.check_password_hash(user.password, PASSWORD):
            user.two_FA = True
            master_totp_key = current_app.config['MASTER_TOTP_SECRET_KEY']
            cipher = Fernet(master_totp_key)
            user.two_FA_key = cipher.encrypt(token.encode('utf-8')).decode("utf-8")
            user.two_FA_type = "TOTP"
            db.session.commit()
            flash('2FA enabled', category='success')

            return redirect(url_for('auth.secrets'))

        else:
            flash('Wrong otp or Password. Key has changed!', category='error')

            return redirect(url_for('auth.two_fa'))

    return render_template("two-FA.html", secret=secret)


@auth.route('/disable2FA', methods=['GET', 'POST'])
@login_required
def disable2fa():
    """
    View globally accessible after logging in, used to disable
    two-factor authentication.

    :return: redirects user to /secrets after disabling 2FA.
    """

    if request.method == 'POST':
        user = User.query.get(current_user.id)
        user_password = request.form['PASSWORD']

        if password_police.check_password_hash(user.password, user_password):
            user.two_FA = False
            user.two_FA_key = None
            user.two_FA_type = None
            db.session.commit()
            flash('2FA disabled', category='error')
        else:
            flash('Wrong password!', category='error')

    return redirect(url_for('auth.secrets'))


@auth.route('/forgot-pass', methods=['GET', 'POST'])
def forgot_pass():
    """
    FORGOT PASSWORD FUNCTIONALITY:

    It is implemented using the following three Views:

    [I] forgot_pass : if user is authenticated, they're automatically redirected
        to auth.otp_check and 'referred_from_forgot_pass' session key is set.
        Else, user enters their registered email address, if it exists,
        an email is sent to it.

    :return: renders template 'forgot_pass.html'
    """
    if current_user.is_authenticated:
        session['EMAIL'] = current_user.email
        return redirect(url_for('auth.pass_reset'))
    else:
        if request.method == 'POST':
            session['EMAIL'] = request.form['EMAIL']
            session['referred_from_forgot_pass'] = True
            user = User.query.filter_by(email=session['EMAIL']).first()

            if user:
                server_otp = two_factor_obj.static_otp(otp_len=6)

                courier = PyCourier(
                    sender_email=sender,
                    sender_password=password,
                    recipients=[session['EMAIL']],
                    message=f"""\
Theorist-Dev Password Reset
OTP: {server_otp} (Valid for 5 minutes)

If you didn't attempt this password-reset, you can safely ignore this email, someone might have typed\ 
it in by mistake
                            """,
                    msg_type="plain",
                    subject="Theorist-Dev Password Reset"
                )
                courier.send_courier()
                session['SERVER_OTP'] = otp_police.generate_password_hash(server_otp, cost=5000)
                session['OTP_TIMESTAMP'] = datetime.now().isoformat()

            return redirect(url_for('auth.otp_check'))

    return render_template("forgot-pass.html")


@auth.route('/OTP-Check', methods=['GET', 'POST'])
@limiter.limit("200 per day")
def otp_check():
    """
    [II] OTPCheck: Accessible iff 'referred_from_forgot_pass' session key is set.
        When this page is called, an OTP is emailed to the registered email address,
        now, If the user POSTS the correct OTP, they are redirected to /pass-reset,
        where they will be allowed to reset their password.

    :return: renders template 'OTPCheck.html'
    """
    if not ('referred_from_forgot_pass' in session and session['referred_from_forgot_pass']):
        abort(403)

    if 'EMAIL' not in session:
        abort(403)

    if request.method == 'POST' and 'SERVER_OTP' in session:
        # check expiry
        otp_timestamp = datetime.fromisoformat(session.get('OTP_TIMESTAMP', '1970-01-01'))
        if datetime.now() > otp_timestamp + timedelta(minutes=5):
            flash('Your One-Time Password has expired. Please log in again.', category='error')
            return redirect(url_for('auth.login'))

        user_otp = request.form['OTP']
        if otp_police.check_password_hash(session['SERVER_OTP'], user_otp):
            del session['SERVER_OTP']
            session['referred_from_otp_check'] = True
            return redirect(url_for('auth.pass_reset'))
        else:
            flash('Wrong otp', category='error')
    elif request.method == 'POST':
        flash('Wrong otp', category='error')

    return render_template("OTPCheck.html")


@auth.route('/pass-reset', methods=['GET', 'POST'])
def pass_reset():
    """
    [III] pass_reset:
    Here the user POSTS a new password.
    Resetting password disables TOTP type 2FA.

    :return: renders template 'pass-reset.html'
    """
    if not (('referred_from_otp_check' in session and session['referred_from_otp_check']) or current_user.is_authenticated):
        abort(403)

    if 'EMAIL' not in session:
        abort(403)

    if request.method == 'POST':
        user = User.query.filter_by(email=session['EMAIL']).first()

        user_password = request.form['PASSWORD']
        check_password = request.form['C-PASSWORD']
        old_password_check = True

        if current_user.is_authenticated:
            old_password = request.form['OLD-PASSWORD']
            old_password_check = password_police.check_password_hash(user.password, old_password)

        if user_password == check_password and old_password_check:
            user.password = password_police.generate_password_hash(user_password)

            if user.two_FA_type == "TOTP":
                user.two_FA = 0
                user.two_FA_key = None
                user.two_FA_type = None

            db.session.commit()

            session.clear()
            flash('Password changed successfully!', category='success')

            return redirect(url_for('auth.login'))

        else:
            flash("The passwords don't match or incorrect old password", category='error')

    return render_template("pass-reset.html", current_user=current_user)


@auth.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    """
    Deletes the account, all the posts and the comments made by the user.
    Users with admin role don't have an option to their delete account,
    it has to be done manually from database terminal (for security purposes).

    :return: renders template 'delete.html'
    """
    if request.method == 'POST' and (current_user.role != "admin" and current_user.role != "author"):
        session['EMAIL'] = current_user.email

        Comment.query.filter_by(user_id=current_user.id).delete()
        User.query.filter_by(email=current_user.email).delete()
        db.session.commit()
        logout_user()

        session.clear()
        flash("Account deleted successfully")

        return redirect(url_for('auth.login'))

    return render_template('delete.html')
