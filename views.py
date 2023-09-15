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
import os
from tert import ElectronicMail
from AuthAlpha import TwoFactorAuth

views = Blueprint("views", __name__, template_folder="templates/views_templates/")
crypt = TwoFactorAuth()
postman = ElectronicMail()


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
    authorized = ["admin", "author"]
    if current_user.role in authorized:
        if request.method == 'POST':
            session['post'] = request.form.get('WYSIWYG')
            session['title'] = request.form.get('title')
            session['time'] = request.form.get('time')
            session['desc'] = request.form.get('desc')
            final_title = ""

            for i in session['title']:
                if i.isalpha() and i != ' ':
                    final_title += i

            session['blog_name'] = final_title[:10] + crypt.static_otp(otp_len=8)

            if len(session['post']) < 1:
                flash('post is too short!', category='error')
            elif len(session['title']) < 1:
                flash('Please add a good title', category='error')
            elif Post.query.filter_by(href="/" + session['blog_name']).first():
                flash('This blog already exists, please change the title to proceed', category='error')
            else:
                new_post = Post(data=session['title'],
                                user_id=current_user.id,
                                author=current_user.name,
                                time=session['time'],
                                desc=session['desc'],
                                href=f"/{session['blog_name']}",
                                email=current_user.email)
                db.session.add(new_post)
                db.session.commit()
                row_count = Post.query.filter_by(user_id=current_user.id).count()
                directory = current_user.email
                if row_count == 1:
                    parent_dir = "templates/blogindex"
                    path = os.path.join(parent_dir, directory)
                    is_dir = os.path.isdir(path)
                    if not is_dir:
                        os.makedirs(path)
                f_name = f"templates/blogindex/{directory}/{session['blog_name']}.html"
                f = open(f_name, "w", encoding="utf-8", newline='')
                f.write("""
<!--This is an auto-generated file-->
{% extends 'blog_base.html' %}
{% block blog %}
{% raw %}
    """)
                f.write(session['post'])
                f.write("""
{% endraw %}
{% endblock blog %}
<!--End of auto-generated file-->
    """)
                f.close()
    else:
        return redirect(url_for('views.apply'))
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
            postman.sendmail("bdickus172@Gmail.com", "Application form", f"email: {apply_email}\n\n"
                                                                         f"name: {name}\n\n"
                                                                         f"Technologies known: {tech}\n\n"
                                                                         f"Role: {app_role}\n\n"
                                                                         f"Qualification: {deg}\n\n"
                                                                         f"Application: {application}\n\n")
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
    author = Post.query.filter_by(href=request.path).first()
    comments = Comment
    if author and author.clicks < 99 and request.method == "GET":
        author.clicks += 1
        db.session.commit()
    if author:
        if request.method == "POST":
            session['data'] = request.form.get('msg')
            new_comment = Comment(name=current_user.name,
                                  email=current_user.email,
                                  data=session['data'],
                                  date=datetime.now(),
                                  user_id=current_user.id,
                                  href=f'/{title}')
            db.session.add(new_comment)
            db.session.commit()
        comments = Comment.query.filter_by(href=f'/{title}').all()
    else:
        abort(404)
    return render_template(f"/blogindex/{author.email}/{title}.html", tdata=title, comments=comments)
