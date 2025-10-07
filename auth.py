import hmac
from cryptography.fernet import Fernet
from flask import Blueprint, render_template, request, flash, redirect, url_for, session, current_app
from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import abort
from __init__ import db, limiter
from datetime import datetime, timedelta, timezone
from models import User, Comment
from PyCourier import PyCourier
from AuthAlpha import PassHashing, TwoFactorAuth, NonPassHashing
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

REDIS_TTL       = 300  # seconds
MAX_ATTEMPTS    = 5    # max number of attempts

def _otp_key(email: str) -> str:  return f"otp:{email.lower()}"
def _n_attempts_key(email: str) -> str: return f"otp_attempts:{email.lower()}"

def verify_redis_otp(email: str, user_otp: str) -> tuple[bool, str]:
    redis_client = current_app.redis
    otp_key = _otp_key(email)
    attempts_key = _n_attempts_key(email)

    # atomic operations
    pipe = redis_client.pipeline()
    pipe.get(attempts_key)
    pipe.get(otp_key)
    results = pipe.execute()

    attempts_count_str = results[0]
    redis_server_otp   = results[1]

    # 1. Check if OTP has expired or doesn't exist
    if redis_server_otp is None:
        return False, "EXPIRED"

    # 2. Check for lockout *before* incrementing attempts
    attempts_count = int(attempts_count_str) if attempts_count_str else 0
    if attempts_count >= MAX_ATTEMPTS:
        return False, "LOCKED"

    # 3. Securely compare the supplied OTP with the stored one
    # hmac.compare_digest prevents timing attacks
    if hmac.compare_digest(redis_server_otp, user_otp):
        # SUCCESS: OTP is correct. Clean up all related keys.
        pipe = redis_client.pipeline()
        pipe.delete(otp_key)
        pipe.delete(attempts_key)
        pipe.execute()
        return True, "SUCCESS"
    else:
        # FAILURE: OTP is incorrect. Atomically increment the attempt counter.
        pipe = redis_client.pipeline()
        pipe.incr(attempts_key)
        # Set expiry on the attempts key to prevent permanent lockout
        pipe.expire(attempts_key, REDIS_TTL)
        pipe.execute()
        return False, "INVALID"

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
@limiter.limit("10/minute;60/hour")
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

            redis_client = current_app.redis
            redis_client.setex(_otp_key(email=session['EMAIL']), REDIS_TTL, server_otp)
            redis_client.delete(_n_attempts_key(email=session['EMAIL']))
            return redirect(url_for('auth.otp'))
        else:
            flash('Email already in use!', category='error')

    return render_template("create.html")


@auth.route('/otp', methods=['GET', 'POST'])
@limiter.limit("10/minute;60/hour")
def otp():
    """

    """
    if not ('referred_from_create' in session and session['referred_from_create']):
        abort(403)

    if 'EMAIL' not in session:
        abort(403)

    if request.method == 'POST':
        user_password = password_police.generate_password_hash(request.form['PASSWORD'])
        user_otp = request.form['OTP']

        otp_comparison_result, status = verify_redis_otp(session['EMAIL'], user_otp)
        if otp_comparison_result:
            try:
                new_user = User(name=session['NAME'],
                                password=user_password,
                                email=session['EMAIL'],
                                active=True,
                                last_confirmed_at=datetime.now(timezone.utc))

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
            if status == "EXPIRED" or status == "LOCKED":
                flash('Your One-Time Password has expired or you have exceeded max attempts. \
                                                            Please log in again.', category='error')
                session.clear()
                return redirect(url_for('auth.create'))

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
@limiter.limit("10/minute;60/hour")
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

                    redis_client = current_app.redis
                    redis_client.setex(_otp_key(email=session['EMAIL']), REDIS_TTL, server_otp)
                    redis_client.delete(_n_attempts_key(email=session['EMAIL']))
                else:
                    session['TOTP_TIMESTAMP'] = datetime.now(timezone.utc).isoformat()

                return redirect(url_for('auth.mfa_login'))
            else:
                session.clear()
                login_user(user, remember=False)
                user.active = True
                user.last_confirmed_at = datetime.now(timezone.utc)
                db.session.commit()
                session.permanent = True
                return redirect(url_for('auth.secrets'))
        else:
            session.clear()
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
            otp_comparison_result, status = verify_redis_otp(session['EMAIL'], user_otp)
            if otp_comparison_result:
                session.clear()
                login_user(user, remember=False)
                user.active = True
                user.last_confirmed_at = datetime.now(timezone.utc)
                db.session.commit()
                session.permanent = True
                return redirect(url_for('auth.secrets'))
            else:
                if status == "EXPIRED" or status == "LOCKED":
                    flash('Your One-Time Password has expired or you have exceeded max attempts. \
                                                                Please log in again.', category='error')
                    session.clear()
                    return redirect(url_for('auth.login'))

                flash('Invalid OTP', category='error')

        elif user and session['2FA_TYPE'] == "TOTP":
            try:
                cipher = Fernet(current_app.config["MASTER_TOTP_SECRET_KEY"])
                encrypted_key = user.two_FA_key
                encrypted_key = encrypted_key.encode("utf-8")
                shared_secret = cipher.decrypt(encrypted_key).decode('utf-8')

                otp_timestamp = datetime.fromisoformat(session.get('TOTP_TIMESTAMP'))
                if datetime.now(timezone.utc) > otp_timestamp + timedelta(minutes=5):
                    flash('Session Expired. Please try again.', category='error')
                    session.clear()
                    return redirect(url_for('auth.login'))

                if two_factor_obj.verify(str(shared_secret), user_otp):
                    session.clear()
                    login_user(user, remember=False)
                    user.active = True
                    user.last_confirmed_at = datetime.now(timezone.utc)
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
                redis_client = current_app.redis
                redis_client.setex(_otp_key(email=session['EMAIL']), REDIS_TTL, server_otp)
                redis_client.delete(_n_attempts_key(email=session['EMAIL']))

            return redirect(url_for('auth.otp_check'))

    return render_template("forgot-pass.html")


@auth.route('/OTP-Check', methods=['GET', 'POST'])
@limiter.limit("200 per day")
def otp_check():
    """

    """
    if not ('referred_from_forgot_pass' in session and session['referred_from_forgot_pass']):
        abort(403)

    if 'EMAIL' not in session:
        abort(403)

    if request.method == 'POST':
        user_otp = request.form['OTP']
        otp_comparison_result, status = verify_redis_otp(session['EMAIL'], user_otp)

        if otp_comparison_result:
            session['referred_from_otp_check'] = True
            return redirect(url_for('auth.pass_reset'))
        else:
            if status == "EXPIRED" or status == "LOCKED":
                flash('Your One-Time Password has expired or you have exceeded max attempts. \
                                                            Please log in again.', category='error')
                session.clear()
                return redirect(url_for('auth.forgot_pass'))

            flash('Wrong otp', category='error')

    return render_template("OTPCheck.html")


@auth.route('/pass-reset', methods=['GET', 'POST'])
def pass_reset():
    """
    [III] pass_reset:

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

        Comment.query.filter_by(user_id=current_user.id).delete()
        User.query.filter_by(email=current_user.email).delete()
        db.session.commit()
        logout_user()

        session.clear()
        flash("Account deleted successfully")

        return redirect(url_for('auth.login'))

    return render_template('delete.html')
