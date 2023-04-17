"""
Group 4 - To Do List Application
By: Hoseok Lee, Ryan Hunt, Shanna Owens, Aaron Bolton
CMSC 495, Spring 2023
University of Maryland Global Campus
"""

# Import dependencies.
import os, csv
from flask import Flask, render_template, request, session, redirect, url_for, flash
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
        page_title = 'To-do List'
    )

# Test Register
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
            flash(error)
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# helper function to read tasks from CSV
def read_tasks():
    tasks = []
    with open('tasks.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            tasks.append(row)
    return tasks

# helper function to write tasks to CSV
def write_tasks(tasks):
    with open('tasks.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(tasks)

@app.route('/create-task', methods=['GET', 'POST'])
def create_task():
    if request.method == 'POST':
        task = request.form['task']
        description = request.form['description']
        due_date = request.form['due_date']

        tasks = read_tasks()
        tasks.append([task, description, due_date])
        write_tasks(tasks)

        return redirect(url_for('home'))

    return render_template('create_task.html')

@app.route('/edit-task/<int:id>', methods=['GET', 'POST'])
def edit_task(id):
    tasks = read_tasks()
    task = tasks[id]

    if request.method == 'POST':
        task = request.form['task']
        description = request.form['description']
        due_date = request.form['due_date']

        task[0] = task
        task[1] = description
        task[2] = due_date

        write_tasks(tasks)

        return redirect(url_for('home'))

    return render_template('edit_task.html', task_id=id, task=task)

@app.route('/delete-task/<int:id>')
def delete_task(id):
    tasks = read_tasks()
    tasks.pop(id)
    write_tasks(tasks)

    return redirect(url_for('home'))

@app.route('/create-list', methods=['GET', 'POST'])
def create_list():
    return render_template('create_task.html')

@app.route('/edit-list', methods=['GET', 'POST'])
def edit_list():
    return render_template('edit_list.html')

@app.route('/delete-list/<int:id>')
def delete_list():
    return render_template('delete_list.html')

if __name__ == '__main__':
    app.run(debug=True)