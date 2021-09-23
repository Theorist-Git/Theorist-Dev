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
from flask import Blueprint, render_template
from flask_login import current_user

# creating an instance of blueprint class for docs.py, later to be registered in the app.

docs = Blueprint('docs', __name__, static_folder="static")


@docs.route("/Cryptography", methods=['GET', 'POST'])
def cryptography_docs():
    return render_template("Cryptography-Docs.html", user=current_user)
