"""
Copyright (C) 2021-2022 Mayank Vats
See license.txt
/* Copyright (C) Mayank Vats - All Rights Reserved
* Unauthorized copying of any file, via any medium is strictly prohibited
* Proprietary and confidential
* Written by Mayank Vats <dev-theorist.e5xna@simplelogin.com>, 2021-2022
*/
"""
from flask import Blueprint, render_template
from flask_login import current_user

# creating an instance of blueprint class for docs.py, later to be registered in the app.

docs = Blueprint('docs', __name__)


@docs.route("/Machine-Learning", methods=['GET', 'POST'])
def ml_index():
    return render_template("ML_Index.html", user=current_user)


@docs.route("/Cryptography", methods=['GET', 'POST'])
def crypt_index():
    return render_template("crypt_Index.html", user=current_user)
