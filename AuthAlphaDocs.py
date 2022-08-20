"""
Copyright (C) Mayank Vats - All Rights Reserved
Unauthorized copying of any file, via any medium is strictly prohibited
Proprietary and confidential
Written by Mayank Vats <dev-theorist.e5xna@simplelogin.com>, 2021-2022
"""

from flask import Blueprint, render_template

AuthAlpha = Blueprint('AuthAlpha', __name__, static_folder="static")


@AuthAlpha.route('/AuthAlpha-Docs', methods=['GET'])
def auth_alpha():
    return render_template('AuthAlpha-docs-index.html')


@AuthAlpha.route('/AuthAlpha-Docs-Page', methods=['GET'])
def auth_alpha_page():
    return render_template('AuthAlpha-docs-page.html')
