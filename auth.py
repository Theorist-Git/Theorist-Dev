"""
Copyright (C) 2021 Mayank Vats
See license.txt
/* Copyright (C) Mayank Vats - All Rights Reserved
* Unauthorized copying of any file, via any medium is strictly prohibited
* Proprietary and confidential
* Contact the author if you want to use it.
* Feel free to use the static and template files
* Written by Mayank Vats <testpass.py@gmail.com>, 2021-2022
*/
If you have this file and weren't given access to it by
the author, you're breaching copyright, delete this file
immediately and contact the author on the aforementioned
email address. Don't worry, you should be fine as long as you don't
use or distribute this software.
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.exceptions import abort
from website import db
from datetime import datetime
from website.models import User, Post, Comment
from website.tert import OTPMethods, ElectronicMail
from AuthAlpha import PassHashing

# creating an instance of blueprint class for auth.py, later to be registered in the app.
auth = Blueprint('auth', __name__)

rn_jesus = OTPMethods()
postman = ElectronicMail()
password_police = PassHashing("argon2id")
otp_police = PassHashing("pbkdf2:sha256")


"""
i)Referrer:
Using request.referrer we are able to restrict user access to certain webpages (like OTP check pages).
We create a list, namely 'auth_ref' with acceptable paths or 'referrals' to these webpages, only through
these paths, the user can access these urls. Otherwise a 403 error is raised.

ii)user=current_user:
This is returned with the template rendered for a specific view for views that don't explicitly use it.
This is on purpose, as we use it to Dynamically display user data (if user is not Anonymous) and is used to
manage the display of certain features. Eg: Users with admin role don't have an option to delete account,
it has to be done manually from database terminal (for security purposes).

iii)Decorators:
-> @auth.route : Used to define routes and accepted method for views in auth.py
-> @login_required : Use to restrict access to certain views. These views are accessible only when the user
is authenticated.
"""


@auth.after_request
def apply_caching(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    print(session)
    return response


@auth.route('/', methods=['GET'])
def home():
    """
    The Home-Page, http://127.0.0.1:5000/
    :return: renders template index.html
    """
    return render_template("index.html", user=current_user)


@auth.route('/create', methods=['GET', 'POST'])
def create():
    """
    Initiates the account creation process,

    1.  To allow multiple users, data is stored in an AES encrypted session.
        For more info see 'session_encryption.py'.

    2.  After that using an instance of SQLALCHEMY() (db), we check if the e-mail id
        (Unique Primary Key) entered by the user already exists. If the checks are passed,
        the user is redirected to auth.otp.

    /* P.S you don't need to worry about regex as it has already been implemented in the
       'create.html' file. */

    :return: renders template 'create.html'
    """
    if not request.referrer:  # 'request.referrer' is 'None' when redirected through an HTML <meta> tag.
        for key in list(session.keys()):
            session.pop(key)
        flash(message="Session and OTP have expired, Please refresh the page!", category="error")
    if request.method == 'POST':
        session['NAME'] = request.form['USERNAME']
        session['EMAIL'] = request.form['EMAIL']
        exists = db.session.query(User.id).filter_by(email=session['EMAIL']).first() is not None
        if exists == 0:
            return redirect(url_for('auth.otp'))
        else:
            flash('email already in use!!', category='error')

    return render_template("create.html", user=current_user)


@auth.route('/otp', methods=['GET', 'POST'])
def otp():
    """
    Used to perform OTP checks specifically for account creation (i.e. for email verification).

    1.  This page is only accessible if referred from '/create' and can persist refresh and POST
        requests while on this page.

    2.  ('GET' request): When this page is called through an authorised referrer, a random OTP
        of length 6 is generated and is e-mailed to the previously stored object with session
        key -> 'EMAIL' (session['EMAIL']). This OTP's pbkdf2:sha256 (50,000 rounds) hash is then
        stored in the encrypted session, to be used for verification of USER_OTP.

    3.  ('POST' request): A user can make a 'POST' request on this page to submit the OTP sent to
        their e-mail, the hash of the USER_OTP is checked against the pre-known hash of the generated
        OTP, if the user enters the correct OTP, the backend database comes into effect, also, as soon
        as the OTP is verified, the key, 'COMP_OTP' is deleted from the session thus making them
        usable only once, hence the name One Time Password.

    4.  A password is now also submitted through this view so that the password is never-ever stored
        in the session in plain-text or otherwise.

        /*
        P.S Again, these OTP hashes exist in the session never for more than 5 minutes.
        */

    5.  Database Entry: A new User object is created which is a class inherited from db.Model
        and UserMixin that stores the Database structure to manage user data. SQLALCHEMY takes
        care of registering a new user entry. The default role of a user is 'user'
        (see User class in models.py). It can be later changed by a user with admin privileges.

    /*  Successful navigation through this view creates an account and logs in the user
        redirecting them to auth.success.
        By default, 'Remember me functionality', is disabled. You can turn it on by changing
        'remember = True'. */

    NOTE: Turning on 'Remember me' breaks the permanent session time-out functionality. The
    session expiring due to not entering OTP still works.

    :return: renders template 'otp.html'
    """
    referrer = request.referrer
    auth_href = [
        "/create",
        "/otp"
    ]
    if referrer:
        if referrer[21:] in auth_href:
            if request.method == 'GET':
                COMP_OTP = rn_jesus.return_random(otp_len=6)
                postman.sendmail(session['EMAIL'],
                                 "ArcisCoding Email Verification",
                                 COMP_OTP,
                                 use_case="registration")
                session['COMP_OTP'] = otp_police.generate_password_hash(COMP_OTP, cost=50000)
            if request.method == 'POST':
                USER_OTP = request.form['OTP']
                PASSWORD = password_police.generate_password_hash(request.form['PASSWORD'])
                if otp_police.check_password_hash(session['COMP_OTP'], USER_OTP):
                    del session['COMP_OTP']
                    new_user = User(name=session['NAME'],
                                    password=PASSWORD,
                                    email=session['EMAIL'],
                                    active=True,
                                    last_confirmed_at=datetime.now())
                    db.session.add(new_user)
                    db.session.commit()
                    login_user(new_user, remember=False)
                    session.permanent = True
                    return redirect(url_for('auth.success'))

                else:
                    flash('Wrong otp', category='error')
        else:
            abort(403)
    else:
        abort(403)
    return render_template("otp.html", user=current_user)


@auth.route('/success')
@login_required
def success():
    """
    The page where the user is redirected on successful creation of account.

    :return: renders template 'success.html'
    """
    return render_template("success.html", user=current_user)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    """
    This page logs the user in;

    1.  ('POST' request): The post request made by the user will contain an e-mail and a password
        , the email is stored in the session while password is not.

    2.  After this, the existence of user is checked, if returned 'True', it is checked if 2FA is
        enabled on this account.

    3.  When user.2FA (A boolean which stores the status of 2FA) is
        i)  False: The user is logged in iff the password is correct.
        ii) True:  User is redirected to 'auth.mfa_login'

    :return: renders template login.html
    """
    if not request.referrer:
        for key in list(session.keys()):
            session.pop(key)
        flash(message="Session and OTP have expired, Please refresh the page!", category="error")
    if request.method == 'POST':
        session['EMAIL'] = request.form['EMAIL']
        PASSWORD = request.form['PASSWORD']
        user = User.query.filter_by(email=session['EMAIL']).first()
        if user:
            if not user.two_FA:
                if password_police.check_password_hash(user.password, PASSWORD):
                    login_user(user, remember=False)
                    user.active = True
                    user.last_confirmed_at = datetime.now()
                    db.session.commit()
                    session.permanent = True
                    return redirect(url_for('auth.secrets'))
                else:
                    flash('Incorrect password, try again.', category='error')
            else:
                if password_police.check_password_hash(user.password, PASSWORD):
                    return redirect(url_for('auth.mfa_login'))
                else:
                    flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/mfa-login', methods=['GET', 'POST'])
def mfa_login():
    """
    This view is responsible for Multi-Factor Authentication during the Login process:

    1.  This view is only accessible through '/login' and associated referrals,
        and can persist refresh and 'POST' requests while on this page.

    2.  ('GET' request): When this page is called through an authorised referrer, a random OTP
        of length 6 is generated and is e-mailed to the previously stored object with session
        key -> 'EMAIL' (session['EMAIL']). This OTP's pbkdf2:sha256 (50,000 rounds) hash is then
        stored in the encrypted session, to be used for verification of USER_OTP.

    3.  ('POST' request): A user can make a 'POST' request on this page to submit the OTP sent to
        their e-mail, the hash of the USER_OTP is checked against the pre-known hash of the generated
        OTP, if the user enters the correct OTP, the user is logged-in, also, as soon as
        the OTP is verified, both the keys, 'COMP_OTP' and 'USER_OTP' are deleted from the session
        thus making them usable only once, hence the name One Time Password.

    /*
    P.S Again, these 'COMP_OTP' hash exists in the session for never more than 5 minutes.
    */

    :return: renders template 'mfa-login.html'
    """
    referrer = request.referrer
    auth_href = [
        "/login",
        "/login?next=%2Flogout",
        "/login?next=%2Faddblog",
        "/login?next=%2Flogout",
        "/login?next=%2Fsecrets",
        "/login?next=%2Ftwo-FA",
        "/login?next=%2Fsuccess",
        "/login?next=%2Fdisable2FA",
        "/login?next=%2Fdelete",
        "/mfa-login"
    ]
    if referrer:
        if referrer[21:] in auth_href:
            if request.method == 'GET':
                COMP_OTP = rn_jesus.return_random(otp_len=6)
                postman.sendmail(session['EMAIL'],
                                 "CitadelCoding Log-in Authorization",
                                 COMP_OTP)
                session['COMP_OTP'] = otp_police.generate_password_hash(COMP_OTP, cost=50000)
            if request.method == 'POST':
                USER_OTP = request.form['OTP']
                if otp_police.check_password_hash(session['COMP_OTP'], USER_OTP):
                    del session['COMP_OTP']
                    user = User.query.filter_by(email=session['EMAIL']).first()
                    login_user(user, remember=False)
                    user.active = True
                    user.last_confirmed_at = datetime.now()
                    db.session.commit()
                    session.permanent = True
                    return redirect(url_for('auth.secrets'))
                else:
                    flash('Wrong otp', category='error')
        else:
            abort(403)
    else:
        abort(403)
    return render_template("mfa-login.html", email=session['EMAIL'])


@auth.route('/logout')
@login_required
def logout():
    """
    Self-explanatory view, logs-out (terminates session) of a user already logged-in.
    Will be automatically called after session times-out after 12 hours.

    :return: redirects to 'auth.login'
    """
    user = User.query.filter_by(email=current_user.email).first()
    user.active = False
    db.session.commit()
    for key in list(session.keys()):
        session.pop(key)
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/secrets', methods=['GET', 'POST'])
@login_required
def secrets():
    """
    Account overview page, gateway to enable 2FA.

    :return: renders template 'secrets.html'
    """
    if not request.referrer:
        try:
            del session['COMP_OTP']
        except KeyError:
            pass
        flash(message="Session and OTP have expired, Please try again!", category="error")
    return render_template("secrets.html", user=current_user)


@auth.route('/about', methods=['GET', 'POST'])
def about():
    """
    About page, TO BE UPDATED

    :return: renders template 'about.html'
    """
    return render_template("about.html", user=current_user)


@auth.route('/two-FA', methods=['GET', 'POST'])
@login_required
def two_fa():
    """
    Only referable from '/secrets', on being called, emails two_FA_otp to the current user,
    If the user POSTS the correct OTP, Two-Factor Authentication is enabled on their account,
    now, they would have to enter an e-mailed otp to log-in. Can be disabled on the Account
    Overview page ('secrets').

    :return: renders template 'two-FA.html'
    """
    referrer = request.referrer
    auth_href = [
        "/secrets",
        "/two-FA"
    ]
    if referrer:
        if referrer[21:] in auth_href:
            if request.method == 'GET':
                COMP_OTP = rn_jesus.return_random(otp_len=6)
                postman.sendmail(current_user.email,
                                 "CitadelCoding Two-Factor-Authentication",
                                 COMP_OTP,
                                 use_case="Enable_2FA")
                session['COMP_OTP'] = otp_police.generate_password_hash(COMP_OTP, cost=50000)
            if request.method == 'POST':
                USER_OTP = request.form['OTP']
                if otp_police.check_password_hash(session['COMP_OTP'], USER_OTP):
                    del session['COMP_OTP']
                    user = User.query.filter_by(email=current_user.email).first()
                    user.two_FA = True
                    db.session.commit()
                    flash('2FA enabled', category='success')
                    return redirect(url_for('auth.secrets'))
                else:
                    flash('Wrong otp', category='error')
        else:
            abort(403)
    else:
        abort(403)
    return render_template("two-FA.html", user=current_user)


@auth.route('/disable2FA')
@login_required
def disable2fa():
    """
    View globally accessible after logging in, used to disable
    two-factor authentication.

    :return: redirects user to /secrets after disabling 2FA.
    """
    user = User.query.filter_by(email=current_user.email).first()
    user.two_FA = False
    db.session.commit()
    flash('2FA disabled', category='error')
    return redirect(url_for('auth.secrets'))


@auth.route('/forgot-pass', methods=['GET', 'POST'])
def forgot_pass():
    """
    FORGOT PASSWORD FUNCTIONALITY:

    It is implemented using the following three Views:

    [I]  forgot_pass : Here the user has to enter their registered email address.
        This view is only accessible through /login and associated pages. If the
        user posts a valid email address, They are redirected to /OTP-check.

    :return: renders template 'forgot_pass.html'
    """
    referrer = request.referrer
    auth_href = [
        "/login",
        "/login?next=%2Flogout",
        "/login?next=%2Faddblog",
        "/login?next=%2Flogout",
        "/login?next=%2Fsecrets",
        "/login?next=%2Ftwo-FA",
        "/login?next=%2Fsuccess",
        "/login?next=%2Fdisable2FA",
        "/login?next=%2Fdelete",
        "/secrets",
        "/forgot-pass"
    ]
    if not request.referrer:
        for key in list(session.keys()):
            session.pop(key)
        flash(message="Session and OTP have expired, Please try again!", category="error")
    if referrer:
        if referrer[21:] in auth_href:
            if request.method == 'POST':
                session['EMAIL'] = request.form['EMAIL']
                user = User.query.filter_by(email=session['EMAIL']).first()
                if user:
                    return redirect(url_for('auth.otp_check'))
                else:
                    flash("No such user exists!", category='error')
        else:
            abort(403)
    else:
        abort(403)
    return render_template("forgot-pass.html")


@auth.route('/OTP-Check', methods=['GET', 'POST'])
def otp_check():
    """
    [II] OTPCheck: Referable only from /forgot_pass. When this page is called, an OTP
        is emailed to the previously entered email address, now, If the user POSTS
        the correct OTP, they are redirected to /pass-reset, where they will be allowed
        to reset their password.

    :return: renders template 'OTPCheck.html'
    """
    referrer = request.referrer
    auth_href = [
        "/forgot-pass",
        "/OTP-Check"
    ]
    if referrer:
        if referrer[21:] in auth_href:
            if request.method == 'GET':
                COMP_OTP = rn_jesus.return_random(otp_len=6)
                postman.sendmail(session['EMAIL'],
                                 "CitadelCoding Password Reset",
                                 COMP_OTP,
                                 use_case="PassReset")
                session['COMP_OTP'] = otp_police.generate_password_hash(COMP_OTP, cost=50000)
            if request.method == 'POST':
                USER_OTP = request.form['OTP']
                if otp_police.check_password_hash(session['COMP_OTP'], USER_OTP):
                    del session['COMP_OTP']
                    return redirect(url_for('auth.pass_reset'))
                else:
                    flash('Wrong otp', category='error')
        else:
            abort(403)
    else:
        abort(403)
    return render_template("OTPCheck.html")


@auth.route('/pass-reset', methods=['GET', 'POST'])
def pass_reset():
    """
    [III]pass_reset: Referable only from /OTP-Check. Here the user POSTS a new password,
        if the user role wasn't admin, their account is updated normally, accounts with admin
        roles will update but with role method overridden. After the updating, the user is
        logged in with the aforementioned protocols.

    :return: renders template 'pass-reset.html'
    """
    referrer = request.referrer
    auth_href = [
        "/OTP-Check",
        "/pass-reset"
    ]
    if referrer:
        if referrer[21:] in auth_href:
            if request.method == 'POST':
                PASSWORD = password_police.generate_password_hash(request.form['PASSWORD'])
                check_password = request.form['C-PASSWORD']
                if password_police.check_password_hash(PASSWORD, check_password):
                    user = User.query.filter_by(email=session['EMAIL']).first()
                    user.password = PASSWORD
                    db.session.commit()
                    flash('Password changed successfully!', category='success')
                    return redirect(url_for('auth.secrets'))
                else:
                    flash("The passwords don't match", category='error')
        else:
            abort(403)
    else:
        abort(403)

    return render_template("pass-reset.html", user=current_user)


@auth.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    """
    Self-explanatory view, deletes the account, all the posts and the comments made by the user.
    Users with admin role don't have an option to their delete account,
    it has to be done manually from database terminal (for security purposes).

    :return: renders template 'delete.html'
    """
    if request.method == 'POST' and current_user.role != "admin":
        session['EMAIL'] = current_user.email
        Post.query.filter_by(user_id=current_user.id).delete()
        Comment.query.filter_by(user_id=current_user.id).delete()
        User.query.filter_by(email=current_user.email).delete()
        db.session.commit()
        logout_user()
        for key in list(session.keys()):
            session.pop(key)
        return redirect(url_for('auth.home'))
    return render_template('delete.html', user=current_user)
