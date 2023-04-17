"""
Group 4 - To Do List Application
By: Hoseok Lee, Ryan Hunt, Shanna Owens, Aaron Bolton
CMSC 495, Spring 2023
University of Maryland Global Campus
"""

# Import dependencies.
import os, csv
from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

# Define globals
app = Flask(__name__)
app.secret_key = os.urandom(16)

# CSV files


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

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with open('users.csv', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['username'] == username:
                    error = 'Username already exists!'
                    return render_template('register.html', error=error)

        password_hash = generate_password_hash(password)
        with open('users.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([username, password_hash])

        session['username'] = username
        return redirect(url_for('home'))
    else:
        return render_template('register.html')
    
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with open('users.csv', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['username'] == username:
                    if check_password_hash(row['password'], password):
                        session['username'] = username
                        return redirect(url_for('home'))
                    else:
                        error = 'Incorrect password!'
                        return render_template('login.html', error=error)
    error = 'Username not found!'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)