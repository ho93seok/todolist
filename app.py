"""
Group 4 - To Do List Application
By: Hoseok Lee, Ryan Hunt, Shanna Owens, Aaron Bolton
CMSC 495, Spring 2023
University of Maryland Global Campus
"""

<<<<<<< HEAD
from flask import Flask, render_template, request, redirect, url_for
import csv, os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=["GET", "POST"])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'password':
            session['logged_in'] = True
            return redirect(url_for('home'))
        else:
            return 'Invalid login'
    return render_template('signin.html')

if __name__ == '__main__':
    app.run(debug=True)
=======
# Import dependencies.
import os
from flask import Flask, render_template

# Define globals
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
>>>>>>> 40193186245dc71df08baa9599ff8fbc84db94dc
