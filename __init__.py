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
from os import getenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis

# Load ENV variables
load_dotenv()

# MySQL server and SQLAlchemy server config
db          = SQLAlchemy()
db_user     = getenv('MYSQL_SERVER_UID')
db_password = quote(getenv('MYSQL_SERVER_PASS'))
db_host     = getenv('MYSQL_SERVER_HOST', 'localhost')
db_database = getenv('MYSQL_SERVER_DB')

if not db_user:
    raise RuntimeError('MYSQL_SERVER_UID not set in .env file. Aborting...')
if not db_password:
    raise RuntimeError('MYSQL_SERVER_PASS not set in .env file. Aborting...')
if not db_database:
    raise RuntimeError('MYSQL_SERVER_DB not set in .env file. Aborting...')

sqlalchemy_database_uri = f'mysql+pymysql://{db_user}:{db_password}@{db_host}/{db_database}'

# REDIS CONFIG: sets us Flask limiter and a general purpose flask server
redis_url           = getenv('REDIS_URL')
redis_limiter_url   = getenv('REDIS_LIMITER_URL')

if not redis_url or not redis_limiter_url:
    raise RuntimeError("REDIS_URL or REDIS_LIMITER_URL is not configured in ENV")

limiter = Limiter(
    get_remote_address,
    default_limits=["2000 per day", "500 per hour"],
    storage_uri=str(redis_limiter_url),
    storage_options={"socket_connect_timeout": 30},
    strategy="fixed-window",  # or "moving-window"
)

redis_client = Redis.from_url(
    redis_url,
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=2,
    health_check_interval=30,
)

try:
    redis_client.ping()
except Exception as e:
    raise RuntimeError("Redis not available")

def create_app():
    """
    This function creates app the ready to run, it takes care of tall the configuration settings
    of the app. It handles all the database relational models, login managers, view blueprint
    registration, error handling and admin panel & related views.
    :return: app (An instance of Flask)
    """
    app = Flask(__name__)
    admin = Admin(app, name="Theorist", template_mode="bootstrap4")

    # Register app-wide CSRF protection
    CSRFProtect(app)

    # Register redis clients with app
    limiter.init_app(app)
    app.redis = redis_client

    # Import crypto keys
    # 1. Flask Secret key       : Used by Flask for signing sessions and other internal uses.
    # 2. CSRF Secret Key        : Used by Flask-WTF to generate and verify CSRF tokens.
    # 3. Master TOTP Secret Key : System wide master key used to encrypt decrypt TOTP shared secrets.
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

    # Flask internal settings
    app.config['SECRET_KEY']                        = flask_secret_key
    app.config['MASTER_TOTP_SECRET_KEY']            = master_totp_secret_key.encode('utf-8')
    app.config['WTF_CSRF_SECRET_KEY']               = wtf_csrf_secret_key
    app.config['SESSION_COOKIE_SECURE']             = True
    app.config['SESSION_COOKIE_HTTPONLY']           = True
    app.config['SESSION_COOKIE_SAMESITE']           = 'Lax'
    app.config['REMEMBER_COOKIE_SECURE']            = True
    app.config['REMEMBER_COOKIE_HTTPONLY']          = True
    app.config['REMEMBER_COOKIE_SAMESITE']          = "Lax"
    app.config['SQLALCHEMY_DATABASE_URI']           = sqlalchemy_database_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS']    = False
    # The session will time out after 720 minutes or 12 hours
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=720)
    app.config['FLASK_ADMIN_SWATCH'] = 'darkly'

    # Blueprints to be registered with the base Flask instance.
    from auth import auth
    from views import views
    from projects import projects

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

    # Importing table schema (see models.py).
    # Register SQLAlchemy object with the app
    db.init_app(app)
    from models import User, Post, Comment

    # Will create tables if they're not there
    with app.app_context():
        db.create_all()

    class AnalyticsView(BaseView):
        def is_accessible(self):
            """
            is_accessible method is overridden method in BaseView and makes it so that only users that
            are authenticated and have an "admin" role can access admin views.
            :return: Boolean (True -> is_accessible) & (False -> is_not_accessible)
            """
            return current_user.is_authenticated and current_user.role == "admin"

        # '/' means /admin/
        @expose('/', methods=['GET', 'POST'])
        def index(self):
            if request.method == 'POST':
                del_email = request.form.get('EMAIL')

                if not del_email:
                    flash("Please enter a valid email address.")
                    return render_template('/admin_views/admin_delete_user.html')

                del_user  = User.query.filter_by(email=del_email).first()

                if del_email and del_user and del_user.role != "admin":
                    Post.query.filter_by(user_id=del_user.id).delete()
                    Comment.query.filter_by(user_id=del_user.id).delete()
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
            return current_user.is_authenticated and current_user.role == "admin"

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
