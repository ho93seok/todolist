"""
Group 4 - To Do List Application
By: Hoseok Lee, Ryan Hunt, Shanna Owens, Aaron Bolton
CMSC 495, Spring 2023
University of Maryland Global Campus
"""

# Import dependencies.
import datetime
import json
import os
import re
import logging
from functools import wraps
from flask import Flask, Markup, session, render_template, flash, request, redirect, url_for
from passlib.hash import sha256_crypt

# Define globals
app = Flask(__name__)
app.secret_key = os.urandom(16)

# Define routes.
@app.route('/')
def index():

    '''Home Page'''

    # Initialize variables.
    site_title = 'Home - Group 4 To-Do List Application'
    loggedin = False
    username = ''

    # Check if the user is logged in.
    if 'username' in session:
        loggedin = True
        username = session['username']

    # Render template.
    return render_template(
        'home.html',
        site_title = site_title,
        site_description = "A to-do list application by Group 4.",
        page_title = 'Welcome'
    )