"""
Copyright (C) 2021 Mayank Vats
See license.txt
/* Copyright (C) Mayank Vats - All Rights Reserved
* Unauthorized copying of any file, via any medium is strictly prohibited
* Proprietary and confidential
* Contact the author if you want to use it.
* Feel free to use the static and template files
* Written by Mayank Vats <testpass.py@gmail.com>, 2021
*/
If you have this file and weren't given access to it by
the author, you're breaching copyright, delete this file
immediately and contact the author on the aforementioned
email address. Don't worry, you should be fine as long as you don't
use or distribute this software.
"""
from flask import Flask, render_template, url_for, flash
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from datetime import timedelta
from flask_login import current_user
from werkzeug.utils import redirect
from flask_wtf.csrf import CSRFProtect
from session_encrytion import EncryptedSession, EncryptedSessionInterface

# We define an SQLAlchemy object
db = SQLAlchemy()
user = current_user


def create_app():
    """
    This function creates app the ready to run, it takes care of tall the configuration settings
    of the app. It handles all the database relational models, login managers, view blueprint
    registration, error handling and admin panel & related views.
    :return: app (An instance of Flask)
    """
    app = Flask(__name__)
    admin = Admin(app)

    CSRFProtect(app)

    # 256 bit security key
    app.config['WTF_CSRF_SECRET_KEY'] = 'xxx'
    app.config['SECRET_KEY'] = 'xxx'
    AES = b'xxx'
    app.config['SESSION_CRYPTO_KEY'] = AES
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:xxx@localhost/xxx'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # The session will timeout after 720 minutes or 12 hours
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=720)
    app.session_interface = EncryptedSessionInterface()

    # This callback can be used to initialize an application for the
    # use with this database setup.  Never use a database in the context
    # of an application not initialized that way or connections will
    # leak.

    db.init_app(app)

    # importing view blueprints from their respective files, to be registered with the flask app.
    # In my case views are distributed in auth.py and views.py files
    from .auth import auth
    from .views import views
    from .docs import docs
    from .AuthAlphaDocs import AuthAlpha

    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(docs, url_prefix='/Projects')
    app.register_blueprint(AuthAlpha, url_prefix='/Projects/Cryptography')

    # 'app.errorhandler' decorator overrides default error pages and replaces them with custom ones
    @app.errorhandler(404)
    def page_not_found(_):
        # note that we set the 404 status explicitly
        return render_template('404.html'), 404

    @app.errorhandler(403)
    def forbidden(_):
        # note that we set the 403 status explicitly
        return render_template('403.html'), 403

    @app.errorhandler(500)
    def internal_server_error(_):
        # note that we set the 500 status explicitly
        return render_template('500.html'), 500

    # After we have defined our database models in models.py,
    # we are importing instances of classes pointing to specific databases.
    from .models import User, Post, Comment

    # Uncomment to remake database models ↓
    # with app.app_context():
    #     db.create_all()

    # Adding admin views
    class MyAdminViews(ModelView):
        def is_accessible(self):
            """
            We override is_accessible method in BaseView and make it so that only users that
            are authenticated and have an "admin" role can access admin views. You can change
            accessibility parameters as you wish.
            :return: Boolean (True -> is_accessible) & (False -> is_not_accessible)
            """
            if current_user.is_authenticated:
                admin_user = User.query.filter_by(role=current_user.role).first()
                res = admin_user.role == "admin"
                return res

        def _handle_view(self, name, **kwargs):
            """
            Output is based on the aforementioned is_accessible() overridden method, and on the
            off chance that the view is_not_accessible, the user is redirected to login page with
            a flash of 403 error.
            """
            if not self.is_accessible():
                flash("Forbidden 403", category="error")
                return redirect(url_for('auth.login'))

    # Adding views to admin (An instance of Admin class in flask_admin)
    admin.add_view((MyAdminViews(User, db.session)))
    admin.add_view((MyAdminViews(Post, db.session)))
    admin.add_view((MyAdminViews(Comment, db.session)))

    # To use flask-login to manage authentication ,we create an instance of LoginManager Class in flask-login.
    # We also have to specify which view will handle authentication, in my case the view is auth.login.
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.session_protection = "strong"
    # Configures an application. This registers an `after_request` call, and
    # attaches this `LoginManager` to it as `app.login_manager`.
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app
