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
from flask import Blueprint, render_template, request

AuthAlpha = Blueprint('AuthAlpha', __name__, static_folder="static")


@AuthAlpha.route('/AuthAlpha-Docs-Index', methods=['GET'])
def AuthAlphaBase():
    return render_template('AuthAlpha-docs-index.html')


@AuthAlpha.route('/AuthAlpha-Docs-Page', methods=['GET'])
def AuthAlphaPage():
    return render_template('AuthAlpha-docs-page.html')
