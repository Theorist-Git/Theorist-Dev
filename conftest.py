"""
Copyright (C) 2021 Mayank Vats
See license.txt
"""
from werkzeug.security import generate_password_hash
from website.models import User, Post, Comment
import datetime
from website import create_app
import pytest

"""
Glossary:

    i) 'Fixtures' initialize tests to a known state in order to run tests in a predictable and repeatable manner.
    
    ii) '@pytest.fixture': This decorator specifies that this function is a fixture with module-level scope. 
        In other words, this fixture will be called one per test module.
        
        These fixtures, 'new_user' and 'new_post', create an instance of User and Post by passing valid arguments 
        to the constructor. 'user' and 'post' is then passed to the test function (return user)/(return post).
        
    iii) 'test_client': This fixture creates the test client using a context manager.
        In order to create the proper environment for testing, Flask provides a test_client helper. 
        This creates a test version of our Flask application (see __init__.py).
        
P.S: cd to project/content root of your project and then paste : pytest -v -W ignore::DeprecationWarning
     to run the tests configured.
"""


@pytest.fixture(scope='module')
def new_user():
    """
    Initializes a new User class (see models.py) with test data to be later tested.

    :return: user, type(user) -> User
    """
    user = User(name="Theorist",
                password=generate_password_hash("p_pass", method='pbkdf2:sha256:101000'),
                email="testpass.py@gmail.com",
                active=True,
                last_confirmed_at=datetime.datetime.now(),
                role="user")
    return user


@pytest.fixture(scope='module')
def new_post(new_user):
    """
    Initializes a new Post class (see models.py) with test data to be later tested.

    :return: post, type(post) -> Post
    """
    post = Post(data="title",
                user_id=new_user.id,
                author=new_user.name,
                time=5,
                desc="desc",
                href="/blog_name",
                email=new_user.email)
    return post


@pytest.fixture(scope='module')
def new_comment(new_user):
    """
        Initializes a new Comment class (see models.py) with test data to be later tested.

        :return: comment, type(comment) -> Comment
        """
    comment = Comment(user_id=new_user.id,
                      name=new_user.name,
                      email=new_user.email,
                      data="comment",
                      date=datetime.date.today(),
                      href="/blog_name", )
    return comment


@pytest.fixture(scope='module')
def test_client():
    """
    Creates a test client using the Flask application configured for testing.
    Establishes an application context to use various functions configured (see __init__.py)

    :yield: testing_client
    """
    flask_app = create_app()
    with flask_app.test_client() as testing_client:
        with flask_app.app_context():
            yield testing_client  # this is where the testing happens!
