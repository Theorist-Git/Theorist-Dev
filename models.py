from __init__ import db
from flask_login import UserMixin
from sqlalchemy.sql import func


class User(db.Model, UserMixin):
    """
    User class inherits UserMixin class from flask_login
    and model is defined using db which is an instance of
    SQLAlchemy(). Used to store User data.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True)
    password = db.Column(db.String(128))
    email = db.Column(db.String(256), unique=True)
    active = db.Column(db.Boolean)
    last_confirmed_at = db.Column(db.DateTime())
    two_FA = db.Column(db.Boolean, default=False, nullable=False)
    two_FA_key = db.Column(db.String(256), default=None, nullable=True)
    two_FA_type = db.Column(db.String(5), default=None, nullable=True)
    role = db.Column(db.String(6), default="user", nullable=False)
    posts = db.relationship('Post')


class Post(db.Model):
    """
    Post class model is defined using db which is an instance of
    SQLAlchemy(). Used to store Posts made by users.
    """
    id = db.Column(db.Integer, primary_key=True)
    post = db.Column(db.UnicodeText, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime(timezone=True), default=func.now(), nullable=False)
    email = db.Column(db.String(256), nullable=False)
    author = db.Column(db.String(150), nullable=False)
    time = db.Column(db.String(10), nullable=False)
    desc = db.Column(db.String(500), nullable=False)
    href = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Comment(db.Model):
    """
    Comment class model is defined using db which is an instance of
    SQLAlchemy(). Used to store Comments made by users on specific Posts.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(100))
    data = db.Column(db.String(500))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    href = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
