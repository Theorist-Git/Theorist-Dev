"""
Copyright (C) 2021 Mayank Vats
See license.txt
"""
from flask import Blueprint, render_template, request

AuthAlpha = Blueprint('AuthAlpha', __name__, static_folder="static")


@AuthAlpha.route('/AuthAlpha-Docs-Index', methods=['GET'])
def AuthAlphaBase():
    return render_template('AuthAlpha-docs-index.html')


@AuthAlpha.route('/AuthAlpha-Docs-Page', methods=['GET'])
def AuthAlphaPage():
    return render_template('AuthAlpha-docs-page.html')
