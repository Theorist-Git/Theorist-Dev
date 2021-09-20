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
    name = db.Column(db.String(150))
    password = db.Column(db.String(150))
    email = db.Column(db.String(254), unique=True)
    active = db.Column(db.Boolean)
    last_confirmed_at = db.Column(db.DateTime())
    two_FA = db.Column(db.Boolean, default=False, nullable=False)
    role = db.Column(db.String(50), default="user", nullable=False)
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
