"""
Group 4 - To Do List Application
By: Hoseok Lee, Ryan Hunt, Shanna Owens, Aaron Bolton
CMSC 495, Spring 2023
University of Maryland Global Campus
"""

# Import dependencies.
import os
from flask import Flask, render_template, request, jsonify
from pusher import Pusher
import json

# Define globals
pusher = Pusher()
app = Flask(__name__)
app.secret_key = os.urandom(16)


# Define routes.
@app.route('/')
def index():

    '''Home Page'''

    # Initialize variables.
    site_title = 'Home - Group 4 To-Do List Application'

    # Render template.
    return render_template(
        'home.html',
        site_title = site_title,
        site_description = "A to-do list application by Group 4.",
        page_title = 'Welcome'
    )

@app.route('/register', methods=["GET", "POST"])
def register():

    '''Registration Page'''

    return render_template(
        'register.html',
        page_title = 'Register'
    )

@app.route('/security-questions', methods=["GET", "POST"])
def security_questions():

    '''Registration Security Questions'''

    return render_template(
        'security-questions.html',
        page_title = 'Register'
    )

@app.route('/password-update', methods=["GET", "POST"])
def password_update():

    '''Password Update (loggin in)'''

    return render_template(
        'password-update.html',
        page_title = 'Password Update'
    )

@app.route('/forgot-password', methods=["GET", "POST"])
def forgot_password():

    '''Forgot Password (logged out)'''

    return render_template(
        'forgot-password.html',
        page_title = 'Forgot Password'
    )

@app.route('/delete-profile', methods=["GET", "POST"])
def delete_profile():

    '''Delete Profile'''

    return render_template(
        'delete-profile.html',
        page_title = 'Delete Profile'
    )

@app.route('/confirm-delete', methods=["GET", "POST"])
def confirm_delete():

    '''Confirm Delete'''

    return render_template(
        'confirm-delete.html',
        page_title = 'Delete Profile'
    )

if __name__ == "__main__":
    app.run(debug=True)
