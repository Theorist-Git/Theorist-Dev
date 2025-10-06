from flask import Blueprint, render_template, request, flash, redirect, url_for
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

projects = Blueprint("projects", __name__, template_folder="templates/projects_templates/")

@projects.after_request
def apply_caching(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Makes sure that back button doesn't take you back to user session after logout.
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

colour_map = {
    "C": "#A8B9CC",               # Light blue (commonly associated with C)
    "C++": "#00599C",             # Blue (official color from C++ branding)
    "Python": "#306998",          # Blue (from Python's logo)
    "Flask": "#000000",           # Black (Flask's primary color)
    "Django": "#092E20",          # Green (Django's branding color)
    "MySQL": "#4479A1",           # Blue (MySQL's logo color)
    "MongoDB": "#47A248",         # Green (MongoDB logo color)
    "Machine Learning": "#FF6F61",# Coral/Orange (represents innovation and creativity)
    "JavaScript": "#F7DF1E",      # Yellow (JavaScript's branding color)
    "HTML": "#E44D26",            # Orange-red (HTML5 logo color)
    "CSS": "#1572B6",             # Blue (CSS3 branding color)
    "Cryptography": "#6A1B9A",    # Deep purple (represents complexity and security)
    "Encryption": "#0288D1",      # Light blue (symbolizing trust and security)
    "Hashing": "#F4511E",         # Deep orange (denotes transformation and integrity)
    "Java": "#007396",            # Blue-green (Java's branding color)
    "React": "#61DAFB",           # Light blue (React's primary logo color)
    "Node.js": "#339933",         # Green (Node.js branding color)
    "Blockchain": "#1F2833",      # Dark gray (represents technology and stability)
    "AI": "#673AB7",              # Violet (symbolizes innovation and intelligence)
    "Auth": "#007bff",            # Blue (symbolizes trust, security, and professionalism)
    "SMTP/Email": "#D44638",      # Red (inspired by Gmail's primary color)
    "Jupyter Notebooks": "#F37626",  # Orange (inspired by the Jupyter logo)
    "CNNs": "#8E44AD",            # Purple (symbolizing complexity and advanced AI)
    "WebCrypto": "#4CAF50",  # Green (symbolizing security and trust)
    "IndexedDB": "#1565C0",  # Deep blue (symbolizing structured data and storage)
}


@projects.route("/", methods=['GET'])
def index():
    return render_template("project_index.html", colour_map=colour_map)