"""
MIT License

Copyright (c) 2025 Mayank Vats

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from flask import Flask, render_template, url_for, flash, request
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from werkzeug.utils import redirect
from urllib.parse import quote
from dotenv import load_dotenv
from os import environ, getenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# We define an SQLAlchemy object
db = SQLAlchemy()
user = current_user

limiter = Limiter(
        get_remote_address,
        default_limits=["2000 per day", "500 per hour"],
        storage_uri="redis://localhost:6379",
        storage_options={"socket_connect_timeout": 30},
        strategy="fixed-window", # or "moving-window"
)


def create_app():
    """
    This function creates app the ready to run, it takes care of tall the configuration settings
    of the app. It handles all the database relational models, login managers, view blueprint
    registration, error handling and admin panel & related views.
    :return: app (An instance of Flask)
    """
    app = Flask(__name__)
    admin = Admin(app, name="Theorist", template_mode="bootstrap4")

    limiter.init_app(app)

    # Ensure CSRF token is present in every request
    CSRFProtect(app)
    load_dotenv()

    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://theorist:%s@localhost/theorist_dev' % \
                              quote(environ['THEORIST_LOCALHOST_PASS'])

    master_totp_secret_key  = getenv("MASTER_TOTP_SECRET_KEY")
    wtf_csrf_secret_key     = getenv("WTF_CSRF_SECRET_KEY")
    flask_secret_key        = getenv("SECRET_KEY")

    if not master_totp_secret_key:
        app.logger.critical("FATAL: Master TOTP key not found. Aborting....")
        raise RuntimeError("MASTER_TOTP_SECRET_KEY not configured in ENV")

    if not wtf_csrf_secret_key:
        app.logger.critical("FATAL: CSRF key not found. Aborting....")
        raise RuntimeError("WTF_CSRF_SECRET_KEY not configured in ENV")

    if not flask_secret_key:
        app.logger.critical("FATAL: Flask secret key not found. Aborting....")
        raise RuntimeError("SECRET_KEY not configured in ENV")

    # 256 bit security key
    app.config['SECRET_KEY'] = flask_secret_key
    app.config['MASTER_TOTP_SECRET_KEY'] = master_totp_secret_key.encode('utf-8')
    app.config['WTF_CSRF_SECRET_KEY'] = wtf_csrf_secret_key
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['REMEMBER_COOKIE_SECURE'] = True
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['REMEMBER_COOKIE_SAMESITE'] = "Lax"
    app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # The session will time out after 720 minutes or 12 hours
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=720)
    # set optional bootswatch theme
    app.config['FLASK_ADMIN_SWATCH'] = 'darkly'

    # This callback can be used to initialize an application for the
    # use with this database setup.  Never use a database in the context
    # of an application not initialized that way or connections will
    # leak.

    db.init_app(app)

    # importing view blueprints from their respective files, to be registered with the flask app.
    from auth import auth
    from views import views
    from projects import projects

    # To be fixed after views are fixed!!!
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(projects, url_prefix='/project')

    # 'app.errorhandler' decorator overrides default error pages and replaces them with custom ones
    # 404(page_not_found), 403(forbidden), 500(internal server error) are set explicitly
    @app.errorhandler(404)
    def page_not_found(_):
        return render_template('404.html'), 404

    @app.errorhandler(403)
    def forbidden(_):
        return render_template('403.html'), 403

    @app.errorhandler(500)
    def internal_server_error(_):
        return render_template('500.html'), 500

    # Importing database model (see models.py).
    from models import User, Post, Comment

    # Will create tables if they're not there
    with app.app_context():
        db.create_all()

    class AnalyticsView(BaseView):
        def is_accessible(self):
            """
            is_accessible method is overridden method in BaseView and make it so that only users that
            are authenticated and have an "admin" role can access admin views.
            :return: Boolean (True -> is_accessible) & (False -> is_not_accessible)
            """
            if not current_user.is_authenticated:
                return False

            admin_user = User.query.get(current_user.id)
            return bool(admin_user and admin_user.role == "admin")

        # '/' means /admin/
        @expose('/', methods=['GET', 'POST'])
        def index(self):
            if request.method == 'POST':
                del_email = request.form['EMAIL']
                del_user= User.query.filter_by(email=del_email).first()

                if del_email and del_user and del_user.role != "admin":
                    import os
                    Post.query.filter_by(user_id=del_user.id).delete()
                    Comment.query.filter_by(user_id=del_user.id).delete()

                    parent_dir = "templates/blogindex"
                    path = os.path.join(parent_dir, del_user.email)

                    is_dir = os.path.isdir(path)
                    if is_dir:
                        from shutil import rmtree
                        rmtree(path)

                    User.query.filter_by(email=del_user.email).delete()
                    db.session.commit()
                    flash("Account deleted successfully")

                else:
                    flash("Email invalid or doesn't exist!")
            return self.render('/admin_views/admin_delete_user.html')

    # Adding admin views
    class MyAdminViews(ModelView):
        def is_accessible(self):
            """
            is_accessible method is overridden method in BaseView and make it so that only users that
            are authenticated and have an "admin" role can access admin views.
            :return: Boolean (True -> is_accessible) & (False -> is_not_accessible)
            """
            if not current_user.is_authenticated:
                return False

            admin_user = User.query.get(current_user.id)
            return bool(admin_user and admin_user.role == "admin")

        def inaccessible_callback(self, name, **kwargs):
            """
            redirect to login page if user doesn't have access
            """
            flash("Forbidden 403", category="error")
            return redirect(url_for('auth.login'))

    # Adding views to Admin Panel (An instance of Admin class in flask_admin)
    admin.add_view((MyAdminViews(User, db.session)))
    admin.add_view((MyAdminViews(Post, db.session)))
    admin.add_view((MyAdminViews(Comment, db.session)))
    admin.add_view(AnalyticsView(name='Delete User', endpoint='/delete_user'))

    # To use flask-login to manage authentication ,we create an instance of LoginManager Class in flask-login.
    # We also have to specify which view will handle authentication, in my case the view is auth.login.
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.session_protection = "strong"

    # Configures an application. This registers an `after_request` call, and
    # attaches this `LoginManager` to it as `app.login_manager`.
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)

    return app
