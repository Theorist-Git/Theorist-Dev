"""
Copyright (C) Mayank Vats - All Rights Reserved
Unauthorized copying of any file, via any medium is strictly prohibited
Proprietary and confidential
Written by Mayank Vats <dev-theorist.e5xna@simplelogin.com>, 2021-2022
"""

from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func


class User(db.Model, UserMixin):
    """
    User class inherits UserMixin class from flask_login
    and model is defined using db which is an instance of
    SQLAlchemy() [See __init__UP.py line 12]. Used to store
    User data.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))
    password = db.Column(db.String(128))
    email = db.Column(db.String(256), unique=True)
    active = db.Column(db.Boolean)
    last_confirmed_at = db.Column(db.DateTime())
    two_FA = db.Column(db.Boolean, default=False, nullable=False)
    two_FA_key = db.Column(db.String(128), default=None, nullable=True)
    two_FA_type = db.Column(db.String(5), default=None, nullable=True)
    role = db.Column(db.String(6), default="user", nullable=False)
    posts = db.relationship('Post')


class Post(db.Model):
    """
    Post class model is defined using db which is an instance of
    SQLAlchemy() [See __init__UP.py line 12]. Used to store
    Posts made by users.
    """
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(100))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    email = db.Column(db.String(254))
    author = db.Column(db.String(150))
    time = db.Column(db.String(10))
    desc = db.Column(db.String(500))
    href = db.Column(db.String(50))
    clicks = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Comment(db.Model):
    """
    Comment class model is defined using db which is an instance of
    SQLAlchemy() [See __init__UP.py line 12]. Used to store
    Comments made by users on specific Posts.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(100))
    data = db.Column(db.String(500))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    href = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
