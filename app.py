"""
Group 4 - To Do List Application
By: Hoseok Lee, Ryan Hunt, Shanna Owens, Aaron Bolton
CMSC 495, Spring 2023
University of Maryland Global Campus
"""

# Import dependencies.
import os
import csv
from random import randrange
import re
from flask import Flask, render_template, request, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash

# Define globals
app = Flask(__name__)
app.secret_key = os.urandom(16)
todo_list = []

# temp list
temp = []

def read_csv( file_name ):
    '''
    Helper function to read items from CSV
    '''
    tasks = []
    with open( file_name, 'r', encoding='utf8') as file:
        reader = csv.reader(file)
        for row in reader:
            tasks.append(row)
    return tasks

def write_csv( file_name, content ):
    '''
    Helper function to write tasks to CSV
    '''
    with open( file_name, 'w', newline='', encoding='utf8') as file:
        writer = csv.writer(file)
        writer.writerows( content )

# Code by Shanna Owens.
def csv_data():

    '''User Database'''

    # create new data list
    data = []
    # read csv file and append each line to data list
    with open('users.csv', 'r', encoding='utf8') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            data.append(row)
    return data

# Code by Shanna Owens.
def csv_security():

    '''Security Database'''

    # create new data list
    data = []
    # read csv file and append each line to data list
    with open('security.csv', 'r', encoding='utf8') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            data.append(row)
    return data

# Define routes.
@app.route( '/', methods=['GET', 'POST'] )
def index():

    '''Home Page'''

    # Initialize variables.
    site_title = 'Home - Group 4 To-Do List Application'
    loggedin = False
    username = ''
    tasks = read_csv( 'tasks.csv' )
    lists = read_csv( 'lists.csv' )
    task_index = 0
    list_index = 0
    delete_task_index = None
    delete_list_index = None

    # Check if the user is logged in.
    if 'username' in session:
        loggedin = True
        username = session['username']

    # If the user submitted a POST request...
    if request.method == 'POST':

        # If the 'list_name' key is in the request...
        if 'list_name' in request.form :

            # If the user indicated the delete list action...
            if request.form['list_name'] == 'delete_list' :

                # Iterate over the lists.
                for task_list in lists :

                    # If the current list ID matches the requested list ID...
                    if task_list[1] == request.form['list_id'] :

                        # Flag the task for deletion.
                        delete_list_index = list_index

                    # Increment the delete list index count
                    list_index = list_index + 1

            # If the user indicated the delete list action...
            if request.form['list_name'] == 'delete_list' :

                # Delete the list.
                del lists[delete_list_index]

            # Update the lists CSV file.
            write_csv( 'lists.csv', lists )

        # If the 'task_name' key is in the request...
        elif 'task_name' in request.form :

            # Iterate over the tasks.
            for task in tasks :

                # If the current task ID matches the requested task ID...
                if task[3] == request.form['task_id'] :

                    # If the user indicated the delete task action...
                    if request.form['task_name'] == 'delete' :

                        # Flag the task for deletion.
                        delete_task_index = task_index

                    #
                    elif request.form['status'] == "complete" :

                        # Change the task status.
                        task[5] = "complete"

                    #
                    elif request.form['status'] == "active" :

                        # Change the task status.
                        task[5] = "active"

                # Increment the delete task index count
                task_index = task_index + 1

            # If the user indicated the delete action...
            if request.form['task_name'] == 'delete' :

                # Delete the task.
                del tasks[delete_task_index]

            # Update the tasks CSV file.
            write_csv( 'tasks.csv', tasks )

    # Render template.
    return render_template(
        'home.html',
        loggedin = loggedin,
        username = username,
        site_title = site_title,
        site_description = "A to-do list application by Group 4.",
        page_title = 'Home',
        tasks = tasks,
        lists = lists
    )

# Code by Shanna Owens.
@app.route('/register', methods=['GET', 'POST'])
def register():

    '''Registration Page'''

    error = None
    # if website request POST, get username/password input
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # prompt user to input username and password fields
        if not username:
            error = 'Please enter a username.'
        elif not password:
            error = 'Please enter a password.'
        # loop through username column in data list
        elif username and password:
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

                    # Get the task lists.
                    task_lists = read_csv( 'lists.csv' )

                    # Clear the task lists.
                    task_lists.clear()

                    # Initialize a Default List.
                    task_list_name = 'Default List'
                    task_list_id = 0

                    # Add the Default List to the lists array.
                    task_lists.append([task_list_name, task_list_id])
                    
                    # Update list file.
                    write_csv( 'lists.csv', task_lists )

                    # redirect to security questions
                    return redirect(url_for('security_questions'))

        # flash any error messages
        flash(error)

        return render_template(
            'register.html',
            page_title = 'Register'
            )

    return render_template(
        'register.html',
        page_title = 'Register'
        )

@app.route('/login', methods=["GET", "POST"])
def login():

    '''Log In Page'''

    temp.clear()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with open('users.csv', 'r', encoding='utf8') as file:
            reader = csv.reader(file, delimiter=',')
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
            return render_template(
                'login.html',
                page_title = 'Log In',
                error=error
                )
    else:
        return render_template(
            'login.html',
            page_title = 'Log In'
        )

@app.route('/admin')
def admin():

    '''Admin Page'''

    return render_template(
        'admin.html',
        page_title = 'My Account',
        )

@app.route('/logout')
def logout():

    '''Define the log out functionality'''

    session.pop('username', None)

    return redirect(url_for('login'))

@app.route('/create-task', methods=['GET', 'POST'])
def create_task():

    '''Define the functionality for creating tasks.'''

    if request.method == 'POST':

        task = request.form['task_name']
        description = request.form['description']
        due_date = str( request.form['due_date'] )
        task_id = str( randrange( 9999 ) )
        list_id = str( request.form['list_id'] ) # Uses Default List ID of 0 for new tasks.
        status = "active"

        tasks = read_csv( 'tasks.csv' )
        tasks.append([task, description, due_date, task_id, list_id, status])
        write_csv( 'tasks.csv', tasks)

        return redirect(url_for('index'))

    return render_template(
        'create-task.html',
        page_title = 'Add a task',
        lists = read_csv( 'lists.csv' )
        )

@app.route('/edit-task/<string:task_id>/<string:task_name>/<string:task_description>/<string:task_due_date>/<string:list_id>', methods=['GET', 'POST'])
def edit_task( task_id, task_name, task_description, task_due_date, list_id ):

    '''Route for editing a task'''

    tasks = read_csv( 'tasks.csv' )

    if request.method == 'POST':

        for task in tasks :

            if task[3] == request.form['task_id'] :

                task_name = request.form['task_name']
                description = request.form['description']
                due_date = request.form['due_date']
                list_id = request.form['list_id']

                task[0] = task_name
                task[1] = description
                task[2] = due_date
                task[4] = list_id

        write_csv( 'tasks.csv', tasks )

        return redirect(url_for('index'))

    return render_template(
        'edit-task.html',
        page_title = 'Edit Task',
        task_id=task_id,
        task_name = task_name,
        description =  task_description,
        due_date = task_due_date,
        list_id =  list_id,
        lists = read_csv( 'lists.csv' )
        )

@app.route('/create-list', methods=['GET', 'POST'])
def create_list():

    '''Route for creating a new list.'''

    if request.method == 'POST':

        task_list_name = request.form['list_name']
        task_list_id = request.form['list_id']

        task_lists = read_csv( 'lists.csv' )
        task_lists.append([task_list_name, task_list_id])
        write_csv( 'lists.csv', task_lists )

        return redirect(url_for('index'))

    return render_template(
        'create-list.html',
        page_title = 'Add a list',
        list_id = randrange( 9999 )
        )

@app.route('/view-list/<string:list_name>/<string:list_id>', methods=['GET', 'POST'])
def view_list( list_name, list_id ):

    '''Route for viewing a list.'''

    # Initialize variables.
    tasks = read_csv( 'tasks.csv' )
    task_list_has_tasks = False

    # Iterate over the tasks...
    for task in tasks :

        # If any task has an ID matching the requested list ID...
        if task[4] == list_id :

            # Update the task_list_has_tasks flag.
            task_list_has_tasks = True

    # Pass the variables to the template for rendering.
    return render_template(
        'view-list.html',
        page_title = 'List',
        list_name = list_name,
        list_id = list_id,
        tasks = tasks,
        task_list_has_tasks = task_list_has_tasks
        )

@app.route('/edit-list/<string:list_name>/<string:list_id>', methods=['GET', 'POST'])
def edit_list( list_name, list_id ):

    '''Route for editing a list'''

    lists = read_csv( 'lists.csv' )

    if request.method == 'POST':

        for task_list in lists :

            if task_list[1] == request.form['list_id'] :

                list_name = request.form['list_name']
                list_id = request.form['list_id']

                task_list[0] = list_name
                task_list[1] = list_id

        write_csv( 'lists.csv', lists )

        return redirect(url_for('index'))

    return render_template(
        'edit-list.html',
        page_title = 'Edit List',
        list_name = list_name,
        list_id =  list_id,
        lists = read_csv( 'lists.csv' )
        )

# Code by Shanna Owens.
@app.route('/security-questions', methods=["GET", "POST"])
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
            with open('security.csv', mode='a', newline='', encoding='utf8') as users:
                writer = csv.writer(users)
                hash_sq1 = generate_password_hash(sq1)
                hash_sq2 = generate_password_hash(sq2)
                hash_sq3 = generate_password_hash(sq3)
                writer.writerow([username, hash_sq1, hash_sq2, hash_sq3])
            # once user input valid, append username and hashed password to database(csv)
            with open('users.csv', mode='a', newline='', encoding='utf8') as file:
                writer = csv.writer(file)
                hash_pass = generate_password_hash(password)
                writer.writerow([username, hash_pass])
                temp.clear()
                # thank user for registering
                flash('Thanks for registering!')
                # redirect to login page
                return redirect('login')
        # flash any error messages
        flash(error)
        return render_template('security-questions.html')
    return render_template('security-questions.html')

# Code by Shanna Owens.
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
            error = 'Please enter your existing password.'
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
        return render_template(
            'update-password.html',
            page_title = 'Change Password'
            )
    return render_template(
        'update-password.html',
        page_title = 'Change Password'
        )

# Code by Shanna Owens.
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
                        if (check_password_hash(sq1_data[i], sq1) is not True
                        or check_password_hash(sq2_data[i], sq2) is not True
                        or check_password_hash(sq3_data[i], sq3) is not True):
                            error = 'Security answers do not match.'
                        else:
                            temp.append(username)
                            return redirect('reset-password')
        if error is not None:
            # flash any error messages
            flash(error)
        return render_template('forgot-password.html')
    return render_template('forgot-password.html')

# Code by Shanna Owens.
@app.route('/reset-password', methods=["GET", "POST"])
def reset_password():

    '''Reset Password'''

    error = None
    # if website request POST, get password input
    # test for user input
    if request.method == "POST":
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        if not password1:
            error = 'Please enter your new password.'
        elif not password2:
            error = 'Please re-enter your new password.'
        elif password1 != password2:
            error = 'Password mismatch.'
        # test new password for password criteria
        else:
            password_check(password1)
            # continue if criteria met
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
                with open('users.csv', mode='w', newline='', encoding='utf8') as users:
                    writer = csv.writer(users)
                    for item in zip(user_data, pswd_data):
                        writer.writerow(item)
                    # clear data
                    data.clear()
                    flash('You have successfully changed your password!')
                    return redirect('login')
            # flash any error messages
            flash(error)
        return render_template('reset-password.html')
    return render_template('reset-password.html')

# Code by Shanna Owens.
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
                if user_data[i] == username and check_password_hash(
                    pswd_data[i], password
                    ) is False:
                    error = 'Wrong password.'
                # check new password meets standard password requirements
                elif user_data[i] == username and check_password_hash(
                    pswd_data[i], password
                    ) is True:
                    return redirect('confirm-delete')
        # flash any error messages
        flash(error)
        return render_template('delete-account.html')
    return render_template('delete-account.html')

# Code by Shanna Owens.
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
                if user_data[i] == username and check_password_hash(
                    pswd_data[i], password
                    ) is False:
                    error = 'Wrong password.'
                # check new password meets standard password requirements
                elif user_data[i] == username and check_password_hash(
                    pswd_data[i], password
                    ) is True:
                    kept_data = []
                    for row in data:
                        if str(row[0]) != username:
                            kept_data.append(row)
                    kept_security = []
                    for row in security:
                        if str(row[0]) != username:
                            kept_security.append(row)
                    # write usernames and passwords back into 'users' database(csv)
                    with open('users.csv', mode='w', newline='', encoding='utf8') as file:
                        writer = csv.writer(file)
                        if kept_data:
                            for item in kept_data:
                                writer.writerow(item)
                            # clear data
                            data.clear()
                    with open('security.csv', mode='w', newline='', encoding='utf8') as file:
                        writer = csv.writer(file)
                        if kept_security:
                            for item in kept_security:
                                writer.writerow(item)
                            # clear security
                            security.clear()
                        # end user session
                        session.pop('username', None)
                        flash('You have successfully deleted your account!')
                        # redirect to login
                        return redirect('login')
        # flash any error messages
        flash(error)
        return render_template('confirm-delete.html')
    return render_template('confirm-delete.html')

# Code by Shanna Owens.
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
    return error

# Code by Shanna Owens.
def new_password_check(password, new_password):

    '''New Password Check'''

    error = None
    username = temp[0]
    # loop through username and password columns in data list
    data = csv_data()
    user_data = [x[0] for x in data]
    pswd_data = [x[1] for x in data]
    # verify old password entered correctly
    for i in range(len(pswd_data)):
        # check if new password input same as old password
        if user_data[i] == username and check_password_hash(pswd_data[i], new_password) is True:
            error = 'Password cannot be the same as last password.'
        elif user_data[i] == username and check_password_hash(pswd_data[i], password) is False:
            error = 'Incorrect password.'
        # check new password criteria
        elif user_data[i] == username and check_password_hash(pswd_data[i], password) is True:
            password_check(new_password)
            # generate new password hash
            if error is None:
                hash_pass = generate_password_hash(new_password)
                pswd_data[i] = hash_pass
                # write usernames and passwords back into 'users' database(csv)
                with open('users.csv', mode='w', newline='', encoding='utf8') as users:
                    writer = csv.writer(users)
                    for item in zip(user_data, pswd_data):
                        writer.writerow(item)
                    # clear data
                    data.clear()
                    flash('You have successfully changed your password!')
    return error

if __name__ == '__main__':
    app.run(debug=True)
