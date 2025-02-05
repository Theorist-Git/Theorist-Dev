"""
Copyright (C) Mayank Vats - All Rights Reserved
Unauthorized copying of any file, via any medium is strictly prohibited
Proprietary and confidential
Written by Mayank Vats <dev-theorist.e5xna@simplelogin.com>, 2021-2023
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_required, current_user
from datetime import datetime
from werkzeug.exceptions import abort
from models import Post, Comment
from __init__ import db
from PyCourier import PyCourier
from AuthAlpha import TwoFactorAuth
from dotenv import load_dotenv
from os import environ
from bleach import clean

load_dotenv()
sender      = environ['SENDER']
password    = environ['PASSWORD']

views       = Blueprint("views", __name__, template_folder="templates/views_templates/")
crypt       = TwoFactorAuth()

allowed_tags  = ['b', 'i', 'u', 'strong', 'em', 'p', 'br', 'ul', 'ol', 'li', 'a', 'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'pre', 'code']
allowed_attrs = {'a': ['href', 'title'], 'img': ['src', 'alt'], 'p': ['class'], 'pre': ['class'], 'code': ['class']}


@views.route('/about', methods=['GET'])
def about():
    """
    About page, TO BE UPDATED

    :return: renders template 'about.html'
    """
    return render_template("about.html")


@views.route('/blogindex', methods=['GET', 'POST'])
def blogindex():
    """
    Index page of the blog, all the blogs created by the users are
    indexed here, is managed by database model Post(see models.py).
    Search function checks for entered keyword/phrase in a split list
    of description and title.

    :return: renders template blogindex.html and a list of all the blog data.
    """
    if request.method == "POST":
        cnt = 0
        match_list = []
        search_query = request.form['search_query'].lower()
        for i in session["blogs"]:
            search_lst = [i.data, i.author, i.desc]
            for j in search_lst:
                if search_query in j.lower():
                    match_list.append(i)
                    cnt += 1
                    break
        if cnt == 0:
            flash("No such blog", category="error")
            match_list = session["blogs"]

    return render_template("blogindex.html", data=Post.query.filter_by().all())


@views.route('/add-blog', methods=['GET', 'POST'])
@login_required
def add_blog():
    """
    Enable registered users to make blog posts, TinyMCE is used as WYSIWYG editor,
    (see /static/plugin/tinymce). The WYSIWYG editor inherently escapes
    script characters providing protection against XSS attacks. The title
    entered by the user is first sanitized and an HTML file is saved under
    blogindex folder, in the sub-folder which is their email address. Separate
    folders are created to each user. The HTML file is stored with 'utf-8 encoding',
    it is an extended base.html document. Comment functionality is embedded
    by default with each Blog.

    :return: renders template add_blog.html
    """
    authorized = ("admin", "author")
    if current_user.role not in authorized:
        return redirect(url_for('views.apply'))

    if request.method == 'POST':
        post  = clean(request.form.get('WYSIWYG'), tags=allowed_tags, attributes=allowed_attrs, strip=True)
        title = clean(request.form.get('title'), tags=allowed_tags, attributes=allowed_attrs, strip=True)
        time  = clean(request.form.get('time'), tags=allowed_tags, attributes=allowed_attrs, strip=True)
        desc  = clean(request.form.get('desc'), tags=allowed_tags, attributes=allowed_attrs, strip=True)
        final_title = ""

        for i in title:
            if i.isalpha() and i != ' ':
                final_title += i

        blog_name = final_title[:10] + crypt.static_otp(otp_len=8)

        if len(blog_name) > 50:
            blog_name = blog_name[:50]

        post_len = len(post)
        title_len = len(title)
        desc_len = len(desc)

        if post_len < 10 or post_len > 65535:
            flash('Post must be between 10 and 65,535 characters long', category='error')
        elif title_len < 1 or title_len > 100:
            flash('Title must be between 1 and 100 characters long', category='error')
        elif desc_len < 1 or desc_len > 500:
            flash('Description must be between 1 and 500 characters long', category='error')
        elif Post.query.filter_by(href="/" + blog_name).first():
            flash('This blog already exists, please change the title to proceed', category='error')
        else:
            new_post = Post(post=post,
                            title=title,
                            email=current_user.email,
                            author=current_user.name,
                            desc=desc,
                            time=time,
                            href=f"/{blog_name}",
                            user_id=current_user.id)
            db.session.add(new_post)
            db.session.commit()

    return render_template("add_blog.html")


@views.route('/apply', methods=['GET', 'POST'])
@login_required
def apply():
    if request.method == "POST":
        apply_email = current_user.email
        name = current_user.name
        tech = request.form.get('tech')
        app_role = request.form.getlist('role')[0]
        deg = request.form.get('deg')
        application = request.form.get('feed')
        if apply_email and name and tech and app_role and deg and application:

            courier = PyCourier(
                sender_email=sender,
                sender_password=password,
                recipients=["bdickus172@gmail.com", ],
                message=f"""\
                Theorist-Dev Blog Author Request:\n
                Email:{apply_email}\n
                Name:{name}\n
                Tech:{tech}\n
                Role:{app_role}\n
                deg:{deg}\n
                Application:{application}\n
                """,
                msg_type="plain",
                subject="Theorist-Dev Blog Author Request"
            )

            courier.send_courier()

            flash("Your application has been sent and will be reviewed in 2-3 days", category="success")
        else:
            flash("Please fill all the fields", category="error")
    return render_template("apply.html")


@views.route('/projects', methods=['GET', 'POST'])
def projects():
    return render_template('projects.html')


@views.route('/generator', methods=['GET', 'POST'])
def gen():
    if request.method == 'POST':
        session['post'] = request.form.get('WYSIWYG')
    return render_template("CodeGen.html")


@views.route('/myblogs', methods=['GET', 'POST'])
@login_required
def myblogs():
    my_blogs = Post.query.filter_by(email=current_user.email).all()
    return render_template("myblogs.html", data=my_blogs)


# Generic view for blogs.
@views.route('<_>', methods=['GET', 'POST'])
def show_blog(_):
    """
    GENERIC FLASK VIEW TO HANDLE ALL NON-EXPLICITLY CODED VIEW REQUESTS:
    This enables the website's blog to function without re-loading everytime
    a blog is posted. This view when passed a parameter checks whether a post
    like that exists in the database or not. If yes, it serves the blog, other-
    -wise raises 404 error.

    :param _: The name of the blog
    :return: renders the template passed in :param.
    Passes title and comments from the database to the HTML document
    which then displays it using JINJA2.
    """
    title = request.path[1:]
    post = Post.query.filter_by(href=request.path).first()
    comments = Comment.query.filter_by(href=request.path).all()

    print(post.post)

    if not post:
        abort(404)

    if request.method == "POST":
        msg = request.form.get('msg')
        new_comment = Comment(name=current_user.name,
                              email=current_user.email,
                              data=msg,
                              date=datetime.now(),
                              user_id=current_user.id,
                              href=f'/{title}')
        db.session.add(new_comment)
        db.session.commit()

    return render_template(f"blog_base.html", title=title, post=post, comments=comments)
