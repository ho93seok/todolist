"""
Group 4 - To Do List Application
By: Hoseok Lee, Ryan Hunt, Shanna Owens, Aaron Bolton
CMSC 495, Spring 2023
University of Maryland Global Campus
"""

# Import dependencies.
from pusher import Pusher
import os
import csv
import re
from flask import Flask, render_template, request, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash

# Define globals
pusher = Pusher()
app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(16)

# temp list
temp = []


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
        page_title = 'To-do List',
        lists = read_lists(),
        tasks = read_tasks()
    )

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():

    '''Registration Page'''

    # if website request POST, get username/password input
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # prompt user to input username and password fields
        if not username:
            error = 'Please enter a username.'
        elif not password:
            error = 'Please enter a password.'
        elif username and password:
            # loop through username column in data list
            data = csv_data()
            user_data = [user[0] for user in data]
            # flash error if username already taken; perform password check if not
            if username in user_data:
                error = 'Username not available.'
            else:
                error = password_check(password)
                if error is None:
                        temp.append(username)
                        temp.append(password)
                        # clear data list
                        data.clear()
                        # redirect to security questions
                        return redirect(url_for('security_questions'))
        # flash any error messages at bottom of page
        flash(error)
        return render_template('register.html')
    return render_template('register.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    temp.clear()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with open('users.csv', 'r') as f:
            reader = csv.reader(f, delimiter=',')
            for row in reader:
                if row[0] == username:
                    if check_password_hash(row[1], password):
                        session['username'] = username
                        return redirect(url_for('index'))
                    else:
                        error = 'Incorrect password!'
                        return render_template('login.html', error=error)
            error = 'Username not found!'
            flash(error)
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')
    
@app.route('/admin/password-update')    
def password_update():
    """function returns page for user to update password (while logged in)"""
    error = None
    # if website request POST, get username/password input
    # test input for correct/existing input combination saved in database(csv)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        new_password = request.form["new_password"]
        # prompt user to input username and password fields
        if not username:
            error = 'Please enter your username.'
        elif not password:
            error = 'Please enter your password.'
        elif not new_password:
            error = 'Please enter your new password.'
        elif username and password and new_password:
            #error = all_checks(username, password, new_password)
            if error is None:
                return redirect('home')
        if error is not None:
            # flash any error messages at bottom of page
            flash(error)
        return render_template('password-update.html')
    return render_template('password-update.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/create-task', methods=['GET', 'POST'])
def create_task():

    if request.method == 'POST':

        task = request.form['task_name']
        description = request.form['description']
        due_date = request.form['due_date']

        tasks = read_tasks()
        tasks.append([task, description, due_date])
        write_tasks(tasks)

        return redirect(url_for('index'))

    return render_template(
        'create-task.html',
        page_title = 'Add a task'
        )

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

        return redirect(url_for('index'))

    return render_template('edit_task.html', task_id=id, task=task)

@app.route('/delete-task/<int:id>')
def delete_task(id):
    tasks = read_tasks()
    tasks.pop(id)
    write_tasks(tasks)

    return redirect(url_for('index'))

#helper function for reading lists.csv
def read_lists():
    lists = []
    with open('lists.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            lists.append(row)
    return lists

#helper function to write lists to lists.csv
def write_lists(lists):
    with open('lists.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(lists)

#list_detail displays list and its contents
@app.route('/list/<int:list_id>')
def list_detail(list_id):
    return redirect(url_for('index'))
    return render_template('list_detail.html', list=list)

#creates lists
@app.route('/create-list', methods=['GET', 'POST'])
def create_list():
    if request.method == 'POST':
        list = request.form['list']

        lists = read_lists()
        lists.append([list])
        write_lists(lists)

        return redirect(url_for('index'))
    return render_template('create_list.html')

#edits lists
@app.route('/edit-list/<int:id>', methods=['GET', 'POST'])
def edit_list():
    lists = read_lists()
    lists = lists[id]

    if request.method == 'POST':
        task = request.form['task']
        description = request.form['description']

        task[0] = description

        write_tasks(lists)

        return redirect(url_for('index'))
    return render_template('edit_list.html', task_id=id, list=list)

#deletes lists
@app.route('/delete-list/<int:id>')
def delete_list(id):
    lists = read_lists()
    lists.pop(id)
    write_lists(lists)
    return redirect(url_for('index'))
def security_questions():

    '''Security Questions'''

    error = None
    username = temp[0]
    password = temp[1]
    if request.method == "POST":
        sq1 = request.form["security question 1"]
        sq2 = request.form["security question 2"]
        sq3 = request.form["security question 3"]
        if not sq1:
            error = 'Please enter an answer for Security Question 1'
        elif not sq2:
            error = 'Please enter an answer for Security Question 2'
        elif not sq3:
            error = 'Please enter an answer for Security Question 3'
        elif sq1 and sq2 and sq3:
            with open('security.csv', mode='a', newline='') as users:
                writer = csv.writer(users)
                hash_sq1 = generate_password_hash(sq1)
                hash_sq2 = generate_password_hash(sq2)
                hash_sq3 = generate_password_hash(sq3)
                writer.writerow([username, hash_sq1, hash_sq2, hash_sq3])
            # once user input valid, append username and hashed password to database(csv)
            with open('users.csv', mode='a', newline='') as f:
                writer = csv.writer(f)
                hash_pass = generate_password_hash(password)
                writer.writerow([username, hash_pass])
                temp.clear()
                # thank user for registering
                flash('Thanks for registering!')
                # redirect to login page
                return redirect('login')
        # flash any error messages at bottom of page
        flash(error)
        return render_template('security-questions.html')
    return render_template('security-questions.html')

@app.route('/update-password', methods=["GET", "POST"])
def update_password():

    '''Update Password (logged in)'''

    error = None
    # if website request POST, get username/password input
    # test input for correct/existing input combination saved in database(csv)
    if request.method == "POST":
        try:
            username = session['username']
        except:
            flash('Your session has timed out.')
            return redirect('login')
        password = request.form["password"]
        new_password = request.form["new_password"]
        # prompt user to input username and password fields
        if not password:
            error = 'Please enter existing your password.'
        elif not new_password:
            error = 'Please enter your new password.'
        elif username and password and new_password:
            temp.append(username)
            error = new_password_check(password, new_password)
            if error is None:
                temp.clear()
                return redirect(url_for('index'))
        if error is not None:
            # flash error message
            flash(error)
        return render_template('update-password.html')
    return render_template('update-password.html')

@app.route('/forgot-password', methods=["GET", "POST"])
def forgot_password():

    '''Forgot Password (logged out)'''

    error = None
    # if website request POST, get username/password input
    # test input for correct/existing input combination saved in database(csv)
    if request.method == "POST":
        username = request.form["username"]
        sq1 = request.form["security question 1"]
        sq2 = request.form["security question 2"]
        sq3 = request.form["security question 3"]
        # prompt user to input username and password fields
        if not username:
            error = 'Please enter your username.'
        elif not sq1:
            error = 'Please enter an answer for Security Question 1'
        elif not sq2:
            error = 'Please enter an answer for Security Question 2'
        elif not sq3:
            error = 'Please enter an answer for Security Question 3'
        elif username and sq1 and sq2 and sq3:
            # loop through username column in data list
            security = csv_security()
            sq0_data = [user[0] for user in security]
            sq1_data = [sq[1] for sq in security]
            sq2_data = [sq[2] for sq in security]
            sq3_data = [sq[3] for sq in security]
            # redirect user to homepage if password confirmed
            if username not in sq0_data:
                error = 'Username does not exist.'
            elif username in sq0_data:
                for i in range(len(sq0_data)):
                    if sq0_data[i] == username:
                        if (check_password_hash(sq1_data[i], sq1) != True 
                        or check_password_hash(sq2_data[i], sq2) != True 
                        or check_password_hash(sq3_data[i], sq3) != True):
                            error = 'Security answers do not match.'
                        else:
                            temp.append(username)
                            return redirect('reset-password')
        if error is not None:
            # flash any error messages at bottom of page
            flash(error)
        return render_template('forgot-password.html')
    return render_template('forgot-password.html')

@app.route('/reset-password', methods=["GET", "POST"])
def reset_password():

    '''Reset Password'''

    error = None
    if request.method == "POST":
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        if not password1:
            error = 'Please enter your new password.'
        elif not password2:
            error = 'Please re-enter your new password.'
        elif password1 != password2:
            error = 'Passwords are not the same.'
        else:
            password_check(password1)
            if error is None:
                username = temp[0]
                # loop through username and password columns in data list
                data = csv_data()
                user_data = [x[0] for x in data]
                pswd_data = [x[1] for x in data]
                # save new password to password data list
                for i in range(len(user_data)):
                    if user_data[i] == username:
                        hash_pass = generate_password_hash(password1)
                        pswd_data[i] = hash_pass
                # write usernames and passwords back into 'users' database(csv)
                with open('users.csv', mode='w', newline='') as users:
                    writer = csv.writer(users)
                    for item in zip(user_data, pswd_data):
                        writer.writerow(item)
                    # clear data
                    data.clear()
                    flash('You have successfully changed your password!')
                    return redirect('login')
            flash(error)
        return render_template('reset-password.html')
    return render_template('reset-password.html')

@app.route('/delete-account', methods=["GET", "POST"])
def delete_account():

    '''Delete Account'''

    error = None
    # if website request POST, get username/password input
    # test input for correct/existing input combination saved in database(csv)
    if request.method == "POST":
        try:
            username = session['username']
        except:
            flash('Your session has timed out.')
            return redirect('login')
        password = request.form["password"]
        # prompt user to input password field
        if not password:
            error = 'Please enter your password.'
        else:
            # loop through username and password columns in data list
            data = csv_data()
            user_data = [user[0] for user in data]
            pswd_data = [pswd[1] for pswd in data]
            # redirect user to homepage if password confirmed
            for i in range(len(user_data)):
                # verify password input against password hash
                if user_data[i] == username and check_password_hash(pswd_data[i], password) == False:
                    error = 'Wrong password.'
                # check new password meets standard password requirements
                elif user_data[i] == username and check_password_hash(pswd_data[i], password) == True:
                    return redirect('confirm-delete')
        flash(error)
        return render_template('delete-account.html')
    return render_template('delete-account.html')

@app.route('/confirm-delete', methods=["GET", "POST"])
def confirm_delete():

    '''Confirm Delete'''

    error = None
    # if website request POST, get username/password input
    # test input for correct/existing input combination saved in database(csv)
    if request.method == "POST":
        try:
            username = session['username']
        except:
            flash('Your session has timed out.')
            return redirect('login')
        password = request.form["password"]
        # prompt user to input password field
        if not password:
            error = 'Please enter your password.'
        else:
            # loop through username and password columns in data list
            security = csv_security()
            data = csv_data()
            user_data = [user[0] for user in data]
            pswd_data = [pswd[1] for pswd in data]
            # redirect user to login if successful deletion
            for i in range(len(user_data)):
                # verify password input against password hash
                if user_data[i] == username and check_password_hash(pswd_data[i], password) == False:
                    error = 'Wrong password.'
                # check new password meets standard password requirements
                elif user_data[i] == username and check_password_hash(pswd_data[i], password) == True:
                    kept_data = []
                    for row in data:
                        if str(row[0]) != username:
                            kept_data.append(row)
                    kept_security = []
                    for row in security:
                        if str(row[0]) != username:
                            kept_security.append(row)
                    # write usernames and passwords back into 'users' database(csv)
                    with open('users.csv', mode='w', newline='') as f:
                        writer = csv.writer(f)
                        if kept_data:
                            for item in kept_data:
                                writer.writerow(item)
                            # clear data
                            data.clear()
                    with open('security.csv', mode='w', newline='') as f:
                        writer = csv.writer(f)
                        if kept_security:
                            for item in kept_security:
                                writer.writerow(item)
                            # clear data
                            security.clear()
                        session.pop('username', None)
                        flash('You have successfully deleted your account!')
                        return redirect('login')
        flash(error)
        return render_template('confirm-delete.html')
    return render_template('confirm-delete.html')

# CSV files
def csv_data():

    '''User Database'''

    # create new data list
    data = []
    # read csv file and append each line to data list
    with open('users.csv', 'r') as f:
        csv_reader = csv.reader(f)
        for row in csv_reader:
            data.append(row)
    return data

def csv_security():
    
    '''Security Database'''

    # create new data list
    data = []
    # read csv file and append each line to data list
    with open('security.csv', 'r') as f:
        csv_reader = csv.reader(f)
        for row in csv_reader:
            data.append(row)
    return data

def password_check(password):

    '''Password Check'''

    error = None
    # string of special characters
    special_char = '`~!@#$%^&*()_+=|\'".,}]{[:;-'
    # check if password length is 12 characters or over
    # contains at least one number, lowercase, uppercase, and special character
    if len(password) < 12:
        error = 'Password must have 12 characters.'
    elif len(password) >= 12:
        if re.search(r'[0-9]', password) is None:
            error = 'Password must contain a number.'
        elif re.search(r'[a-z]', password) is None:
            error = 'Password must contain a lowercase letter.'
        elif re.search(r'[A-Z]', password) is None:
            error = 'Password must contain an uppercase letter.'
        elif not any(sc in special_char for sc in password):
            error = 'Password must contain a special character.'
            # once user input valid, append username and hashed password to database(csv)
    return error

def new_password_check(password, new_password):

    '''New Password Check'''

    error = None
    username = temp[0]
    # loop through username and password columns in data list
    data = csv_data()
    user_data = [x[0] for x in data]
    pswd_data = [x[1] for x in data]
    # verify old password entered correctly; save new password to password data list
    for i in range(len(pswd_data)):
        # check if new password input same as old password
        if user_data[i] == username and check_password_hash(pswd_data[i], new_password) == True:
            error = 'Password cannot be the same as last password.'
        elif user_data[i] == username and check_password_hash(pswd_data[i], password) == False:
            error = 'Incorrect password.'
        elif user_data[i] == username and check_password_hash(pswd_data[i], password) == True:
            password_check(new_password)
            if error is None:
                hash_pass = generate_password_hash(new_password)
                pswd_data[i] = hash_pass
                # write usernames and passwords back into 'users' database(csv)
                with open('users.csv', mode='w', newline='') as users:
                    writer = csv.writer(users)
                    for item in zip(user_data, pswd_data):
                        writer.writerow(item)
                    # clear data
                    data.clear()
                    flash('You have successfully changed your password!')
    return error

if __name__ == '__main__':
    app.run(debug=True)