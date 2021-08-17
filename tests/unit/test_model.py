"""
Copyright (C) 2021 Mayank Vats
See license.txt
"""
from flask_login import login_user, current_user, logout_user

"""
This module tests database models, fixtures are defined in conftest.py.
"""


def test_new_user(new_user):
    """
    GIVEN a User model
    WHEN a new User is created
    THEN check the email, hashed_password, and role fields are defined correctly
    """
    assert new_user.email == 'testpass.py@gmail.com'
    assert new_user.password != 'p_pass'
    assert new_user.role == 'user'


def test_login_logout(new_user, test_client):
    """
    GIVEN a User model and a test client
    WHEN Login and Logout is attempted
    THEN check whether authentication works correctly
    """
    test_client.get('/login')
    login_user(new_user, remember=False)
    assert current_user.is_authenticated is True
    logout_user()
    assert current_user.is_authenticated is False


def test_new_post(new_post, new_user):
    """
    Given a Post model
    WHEN a new Post is created
    THEN check the data, user_id, author, time, desc, href and email are defined correctly.

    P.S: requires a User model too.
    """
    assert new_post.data == "title"
    assert new_post.user_id == new_user.id
    assert new_post.author == new_user.name
    assert new_post.time == 5
    assert new_post.desc == "desc"
    assert new_post.href == "/blog_name"
    assert new_post.email == new_user.email


def test_new_comment(new_comment, new_user):
    """
    Given a Comment model
    WHEN a new Comment is created
    THEN check the data, user_id, href and email are defined correctly.

    P.S: requires a User model too.
    """
    assert new_comment.data == "comment"
    assert new_comment.user_id == new_user.id
    assert new_comment.email == new_user.email
    assert new_comment.href == "/blog_name"
