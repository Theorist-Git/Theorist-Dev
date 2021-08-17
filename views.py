"""
Copyright (C) 2021 Mayank Vats
See license.txt
"""
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import datetime
from werkzeug.exceptions import abort
from .models import Post, Comment
from . import db
import os
from website import tert

views = Blueprint('views', __name__)
otp_gen = tert.OTPMethods
postman = tert.ElectronicMail
misc = tert.Misc


@views.route('/addblog', methods=['GET', 'POST'])
@login_required
def addblog():
    """
    Enable registered users to make blog posts, Powered by TinyMCE,
    (see /static/plugin/tinymce). The WYSIWYG editor inherently escapes
    script characters providing protection against XSS attacks. The title
    entered by the user is first sanitized and an HTML file is saved under
    user_files folder, in the sub-folder which is their email address. Separate
    folders are created to each user. The HTML file is stored with 'utf-8 encoding',
    it is an extended base.html document. Comment functionality is embedded
    by default with each Blog.

    :return: renders template addblog.html
    """
    global link
    authorized = ["admin", "author"]
    if current_user.role in authorized:
        if request.method == 'POST':
            post = request.form.get('editor')
            title = request.form.get('title')
            author = request.form.get('author')
            time = request.form.get('time')
            desc = request.form.get('desc')
            final_title = ""
            for i in title:
                if i.isalpha():
                    final_title += i
            blog_name = final_title[:10].replace(' ', '')
            blog_name += otp_gen.return_random(otp_len=8)

            if len(post) < 1:
                flash('post is too short!', category='error')
            elif len(title) < 1:
                flash('Please add a good title', category='error')
            elif Post.query.filter_by(href="/" + blog_name).all():
                flash('This blog already exists, please change the title to proceed', category='error')
            else:
                new_post = Post(data=title, user_id=current_user.id, author=current_user.name, time=time, desc=desc,
                                href=f"/{blog_name}", email=current_user.email)
                db.session.add(new_post)
                db.session.commit()
                row_count = Post.query.filter_by(user_id=current_user.id).count()
                directory = current_user.email
                if row_count == 1:
                    parent_dir = "templates/User_files"
                    path = os.path.join(parent_dir, directory)
                    isFile = os.path.isfile(path)
                    if not isFile:
                        os.mkdir(path)
                f_name = f"templates//User_files//{directory}//{blog_name}.html"
                import io
                f = io.open(f_name, "w", encoding="utf-8")
                f.write("""{% extends 'base.html' %}
    {% block content %}
    <title>CitadelBlog</title>
    <link rel="shortcut icon" type="image/jpg" href="/static/favicon.ico"/>
    <div class="main mx-5 my-3" style="border:2px solid black;">
    <div class="main mx-5 my-3" style = "font-family:arial;">""")
                f.write(post)
                f.write("""</div>
    </div>
    <!-- Main Body -->
    {% if current_user.is_authenticated %}
    <div style="background-color: #000000">
    <section>
        <div class="container">
            <div class="row">
                <div class="my-3">
                    <form action = {{tdata}} method = "POST" id="algin-form">
                        <div class="form-group">
                            <h4>Leave a comment</h4> <label>Message</label> <textarea name="msg" id="msg" cols="30" rows="5"
                             class="form-control" style="background-color: white;"></textarea>
                        </div>
                        <div> <label>Name: &emsp; {{current_user.name}}</label></div>
                        <div> <label>Email: &emsp; {{current_user.email}}</label></div>
    
                        <div class="form-group">
                            <p class="text-secondary">If you wish, you can sub to our <a href="/404" class="alert-link">
                            Newsletter</a></p>
                        </div>
                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                        <button type="submit" id = "s_ubmit" class="btn btn-primary btn-lg btn-block">Submit</button>
                    </form>
                </div>
                <div class="my-4">
                    <h1>Comments</h1>
                    {% for i in comments %}
                    <div class="comment col-12 my-3">
                        <h4>{{ i.name }}</h4> <span>- {{ i.date }}</span> <br>
                        <p>{{ i.data }}</p>
                    </div>
                    {% endfor %}
                </div>
    
            </div>
        </div>
    </section>
    </div>
    {% endif %}
    <style>
      @media(min-width:568px) {
        .end {
            margin-left: auto
        }
    }
    
    @media(max-width:768px) {
        #post {
            width: 100%
        }
    }
    
    #clicked {
        padding-top: 1px;
        padding-bottom: 1px;
        text-align: center;
        width: 100%;
        background-color: #ecb21f;
        border-color: #a88734 #9c7e31 #846a29;
        color: black;
        border-width: 1px;
        border-style: solid;
        border-radius: 13px
    }
    
    #profile {
        background-color: unset
    }
    
    #post {
        margin: 10px;
        padding: 6px;
        padding-top: 2px;
        padding-bottom: 2px;
        text-align: center;
        background-color: #ecb21f;
        border-color: #a88734 #9c7e31 #846a29;
        color: black;
        border-width: 1px;
        border-style: solid;
        border-radius: 13px;
        width: 50%
    }
    
    #nav-items li a,
    #profile {
        text-decoration: none;
        color: rgb(224, 219, 219);
        background-color: black
    }
    
    .comments {
        margin-top: 5%;
        margin-left: 20px
    }
    
    .darker {
        border: 1px solid #ecb21f;
        background-color: black;
        float: right;
        border-radius: 5px;
        padding-left: 40px;
        padding-right: 30px;
        padding-top: 10px
    }
    
    .comment {
        border: 1px solid rgba(16, 46, 46, 1);
        background-color: rgba(16, 46, 46, 0.973);
        float: left;
        border-radius: 5px;
        padding-left: 40px;
        padding-right: 30px;
        padding-top: 10px
    }
    
    .comment h4,
    .comment span,
    .darker h4,
    .darker span {
        display: inline
    }
    
    .comment p,
    .comment span,
    .darker p,
    .darker span {
        color: rgb(184, 183, 183)
    }
    
    h1,
    h4 {
        color: white;
        font-weight: bold
    }
    
    label {
        color: rgb(212, 208, 208)
    }
    
    #align-form {
        margin-top: 20px
    }
    
    .form-group p a {
        color: white
    }
    
    #checkbx {
        background-color: black
    }
    
    #darker img {
        margin-right: 15px;
        position: static
    }
    
    .form-group input,
    .form-group textarea {
        background-color: black;
        border: 1px solid rgba(16, 46, 46, 1);
        border-radius: 12px
    }
    
    form {
        border: 1px solid rgba(16, 46, 46, 1);
        background-color: rgba(16, 46, 46, 0.973);
        border-radius: 5px;
        padding: 20px
    }
    </style>
    {% endblock content %}""")
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
        search_query = request.form['search_query']
        searched_blogs = blogs[0:0]
        for i in fblogs:
            if search_query.upper() in misc.capitalize_list(i.data.split()) or search_query.upper() in misc.capitalize_list(i.desc.split()) or search_query.upper() in misc.capitalize_list(i.author.split()):
                searched_blogs.append(i)
                blogs = searched_blogs
        if blogs == fblogs:
            flash("No such blog!", category="error")
    return render_template("blogindex.html", data=blogs)


@views.route('/feedback', methods=['GET', 'POST'])
def feedback():
    """
    Feedback form, the response submitted is submitted to
    the admin. UNDER CONSTRUCTION

    :return: renders template feedback.html
    """
    if request.method == "POST":
        feed = request.form.get('feed')
        postman.sendmail("bdickus172@gmail.com", "User Feedback", feed, role="admin")
    return render_template("feedback.html")


@login_required
@views.route('/apply', methods=['GET', 'POST'])
def apply():
    if request.method == "POST":
        apply_email = current_user.email
        name = request.form.get('name')
        tech = request.form.get('tech')
        app_role = request.form.getlist('role')[0]
        deg = request.form.get('deg')
        application = request.form.get('feed')
        if apply_email and name and tech and app_role and deg and application:
            postman.sendmail("bdickus172@Gmail.com", "Application form",
                             f"email: {apply_email}\n\n"
                             f"name: {name}\n\n"
                             f"Technologies known: {tech}\n\n"
                             f"Role: {app_role}\n\n"
                             f"Qualification: {deg}\n\n"
                             f"Application: {application}\n\n",
                             role="admin")
            flash("Your application has been sent and will be reviewed in 2-3 days", category="success")
        else:
            flash("Please fill all the fields", category="error")
    return render_template("apply.html", current_user=current_user)


@views.route('/modelindex', methods=['GET', 'POST'])
def modelindex():
    return render_template('modelindex.html')


# Generic view for blogs.
@views.route('/<some_place>', methods=['GET', 'POST'])
def show_blog(some_place):
    """
    GENERIC FLASK VIEW TO HANDLE ALL NON-EXPLICITLY CODED VIEW REQUESTS:
    This enables the website's blog to function without re-loading everytime
    a blog is posted. This view when passed a parameter check whether a post
    like that exists in the database or not. If yes, it serves the blog, other-
    -wise raises 404 error.

    :param some_place: The name of the blog
    :return: renders the template passed in :param.
    Passes title and comments from the database to the HTML document
    which then displays it using JINJA2.
    """
    title = request.path[1:]
    author = Post.query.filter_by(href=request.path).first()
    if author:
        if request.method == "POST":
            data = request.form.get('msg')
            new_comment = Comment(name=current_user.name, email=current_user.email, data=data, date=datetime.now(), user_id=current_user.id, href=f'/{title}')
            db.session.add(new_comment)
            db.session.commit()
        comments = Comment.query.filter_by(href=f'/{title}').all()
    else:
        abort(404)
    return render_template(f"//User_files//{author.email}//{title}.html", tdata=title, comments=comments)