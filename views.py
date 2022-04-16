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
from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_required, current_user
from datetime import datetime
from werkzeug.exceptions import abort
from .models import Post, Comment
from . import db
import os
from website.tert import OTPMethods, ElectronicMail, Misc

views = Blueprint('views', __name__)
otp_gen = OTPMethods()
postman = ElectronicMail()
misc = Misc()


@views.route('/addblog', methods=['GET', 'POST'])
@login_required
def addblog():
    """
    Enable registered users to make blog posts, Powered by TinyMCE,
    (see /static/plugin/tinymce). The WYSIWYG editor inherently escapes
    script characters providing protection against XSS attacks. The title
    entered by the user is first sanitized and an HTML file is saved under
    blogindex folder, in the sub-folder which is their email address. Separate
    folders are created to each user. The HTML file is stored with 'utf-8 encoding',
    it is an extended base.html document. Comment functionality is embedded
    by default with each Blog.

    :return: renders template addblog.html
    """
    authorized = ["admin", "author"]
    if current_user.role in authorized:
        if request.method == 'POST':
            session['post'] = request.form.get('editor')
            session['title'] = request.form.get('title')
            session['time'] = request.form.get('time')
            session['desc'] = request.form.get('desc')
            final_title = ""
            for i in session['title']:
                if i.isalpha():
                    final_title += i
            session['blog_name'] = final_title[:10].replace(' ', '') + otp_gen.return_random(otp_len=8)

            if len(session['post']) < 1:
                flash('post is too short!', category='error')
            elif len(session['title']) < 1:
                flash('Please add a good title', category='error')
            elif Post.query.filter_by(href="/" + session['blog_name']).all():
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
                    isFile = os.path.isfile(path)
                    if not isFile:
                        os.mkdir(path)
                f_name = f"templates//blogindex//{directory}//{session['blog_name']}.html"
                import io
                f = io.open(f_name, "w", encoding="utf-8")
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
    return render_template("addblog.html", user=current_user)


@views.route('/blogindex', methods=['GET', 'POST'])
def blogindex():
    """
    Index page of the blog, all the blogs created by the users are
    indexed here, is managed by database model Post(see models.py).
    Search function checks for entered keyword/phrase in a split list
    of description and title.

    :return: renders template blogindex.html and a list of all the blog data.
    """
    fblogs = Post.query.filter_by().all()
    blogs = fblogs
    if request.method == "POST":
        session['search_query'] = request.form['search_query']
        searched_blogs = blogs[0:0]
        for i in fblogs:
            if session['search_query'].upper() in misc.capitalize_list(
                    i.data.split()) or session['search_query'].upper() in misc.capitalize_list(
                    i.desc.split()) or session['search_query'].upper() in misc.capitalize_list(i.author.split()):
                searched_blogs.append(i)
                blogs = searched_blogs
        if blogs == fblogs:
            flash("No such blog!", category="error")
    return render_template("blogindex.html", data=blogs)


@views.route('/feedback', methods=['GET', 'POST'])
def feedback():
    """
    Feedback form, the response submitted is submitted to
    the admin.

    :return: renders template feedback.html
    """
    if request.method == "POST":
        session['feed'] = request.form.get('feed')
        if len(session['feed']) > 10:
            postman.sendmail("bdickus172@gmail.com", "User Feedback", session['feed'])
            flash("Your feedback has been recorded!", category="success")
        else:
            flash("The message needs to be longer", category="error")
    return render_template("feedback.html")


@views.route('/apply', methods=['GET', 'POST'])
@login_required
def apply():
    if request.method == "POST":
        session['apply_email'] = current_user.email
        session['name'] = request.form.get('name')
        session['tech'] = request.form.get('tech')
        session['app_role'] = request.form.getlist('role')[0]
        session['deg'] = request.form.get('deg')
        session['application'] = request.form.get('feed')
        if session['apply_email'] and session['name'] and session['tech'] and session['app_role'] and session['deg'] and session['application']:
            postman.sendmail("bdickus172@Gmail.com", "Application form", f"email: {session['apply_email']}\n\n"
                                                                         f"name: {session['name']}\n\n"
                                                                         f"Technologies known: {session['tech']}\n\n"
                                                                         f"Role: {session['app_role']}\n\n"
                                                                         f"Qualification: {session['deg']}\n\n"
                                                                         f"Application: {session['application']}\n\n")
            flash("Your application has been sent and will be reviewed in 2-3 days", category="success")
        else:
            flash("Please fill all the fields", category="error")
    return render_template("apply.html", current_user=current_user)


@views.route('/Projects', methods=['GET', 'POST'])
def modelindex():
    return render_template('modelindex.html')


@views.route('/generator', methods=['GET', 'POST'])
def gen():
    if request.method == 'POST':
        session['post'] = request.form.get('editor')
        print(session['post'])
    return render_template("CodeGen.html", user=current_user)


# Generic view for blogs.
@views.route('<_>', methods=['GET', 'POST'])
def show_blog(_):
    """
    GENERIC FLASK VIEW TO HANDLE ALL NON-EXPLICITLY CODED VIEW REQUESTS:
    This enables the website's blog to function without re-loading everytime
    a blog is posted. This view when passed a parameter check whether a post
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
    return render_template(f"//blogindex//{author.email}//{title}.html", tdata=title, comments=comments)
