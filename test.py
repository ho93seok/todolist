
#imports
import csv
import re
from flask import Flask, request, render_template, flash, redirect
from passlib.hash import sha256_crypt

# instance of Flask class
app = Flask(__name__)




### below functions are for registration/edit profile(password update and user delete)
def csv_data():
    """function reads, stores and returns data from database(csv)"""
    # create new data list
    data = []
    # read csv file and append each line to data list
    with open('users.csv', 'r') as csvfile:
        csv_reader = csv.reader(csvfile)
        for row in csv_reader:
            data.append(row)
    return data

def password_check(password):
    """function checks password criteria"""
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
    """"""
    error = None
    # check if new password input same as old password
    if new_password == password:
        error = 'Password cannot be the same as last password.'
    if error is None:
        # check password criteria
        password_check(new_password)
        if error is None:
            # loop through username and password columns in data list
            data = csv_data()
            user_data = [x[0] for x in data]
            pswd_data = [x[1] for x in data]
            # verify old password entered correctly; save new password to password data list
            for i, _ in enumerate(pswd_data):
                if sha256_crypt.verify(password, pswd_data[i]):
                    hash_pass = sha256_crypt.hash(new_password)
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

def all_checks(username, password, new_password):
    """function to initiate password checks for password update"""
    # loop through username and password columns in data list
    data = csv_data()
    user_data = [x[0] for x in data]
    pswd_data = [x[1] for x in data]
    # flash error if username not registered; return to password update
    if username not in user_data:
        error = 'Incorrect username.'
        # redirect user to homepage if username and password match
    if username in user_data:
        for i, _ in enumerate(user_data):
            # verify password input against password hash
            if user_data[i] == username and not sha256_crypt.verify(password, pswd_data[i]):
                error = 'Wrong username or password.'
            # check new password meets standard password requirements
            elif user_data[i] == username and sha256_crypt.verify(password, pswd_data[i]):
                error = new_password_check(password, new_password)
    return error

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
            error = all_checks(username, password, new_password)
            if error is None:
                return redirect('home')
        if error is not None:
            # flash any error messages at bottom of page
            flash(error)
        return render_template('password_update.html')
    return render_template('password_update.html')

def forgot_password(): ####IN PROGRESS####
    """function returns page for user to change forgotten password (not logged in)"""
    error = None
    # if website request POST, get username/password input
    # test input for correct/existing input combination saved in database(csv)
    if request.method == "POST":
        username = request.form["username"]
        new_password = request.form["new_password"]
        # prompt user to input username and password fields
        if not username:
            error = 'Please enter your username.'
        elif not new_password:
            error = 'Please enter your new password.'
        elif username and new_password:
            error = all_checks(username, new_password)
            if error is None:
                return redirect('login')
        if error is not None:
            # flash any error messages at bottom of page
            flash(error)
        return render_template('forgot_password.html')
    return render_template('forgot_password.html')

def confirm_deletion(): ####IN PROGRESS####
    """"""
    error = None
    

def delete_profile_stage2(username, password): ####IN PROGRESS####
    """"""
    # loop through username and password columns in data list
    data = csv_data()
    user_data = [user[0] for user in data]
    pswd_data = [pswd[1] for pswd in data]
    # flash error if username not registered; return to password update
    if username not in user_data:
        error = 'Incorrect username.'
    # redirect user to homepage if username and password match
    if username in user_data:
        for i, _ in enumerate(user_data):
            # verify password input against password hash
            if user_data[i] == username and not sha256_crypt.verify(password, pswd_data[i]):
                error = 'Wrong username or password.'
            # check new password meets standard password requirements
            elif user_data[i] == username and sha256_crypt.verify(password, pswd_data[i]):


                kept_data = []
                for row in data:
                    if str(row[0]) != username:
                        kept_data.append(row)
                # write usernames and passwords back into 'users' database(csv)
                with open('users.csv', mode='w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(kept_data)
                    # clear data
                    data.clear()
                    flash('You have successfully deleted your account!')
    return error

def delete_profile():
    """function returns page for user to change forgotten password (not logged in)"""
    error = None
    # if website request POST, get username/password input
    # test input for correct/existing input combination saved in database(csv)
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # prompt user to input username and password fields
        if not username:
            error = 'Please enter your username.'
        elif not password:
            error = 'Please enter your password.'
        elif username and password:
            delete_profile_stage2(username, password)
            if error is None:
                return redirect('login')
        if error is not None:
            # flash any error messages at bottom of page
            flash(error)
        return render_template('delete_profile.html')
    return render_template('delete_profile.html')

@app.route('/register', methods=["GET", "POST"])
def register():
    """user registration form"""
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
                    # once user input valid, append username and hashed password to database(csv)
                    with open('users.csv', mode='a', newline='') as users:
                        writer = csv.writer(users)
                        hash_pass = sha256_crypt.hash(password)
                        writer.writerow([username, hash_pass])
                        # clear data list
                        data.clear()
                        security_questions(username)
                        # redirect to security questions
                        return redirect('security_questions')
        # flash any error messages at bottom of page
        flash(error)
        return render_template('register.html')
    return render_template('register.html')

@app.route('/security_questions', methods=["GET", "POST"])
def security_questions(username):
    """security questions form"""
    error = None
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
                hash_sq1 = sha256_crypt.hash(sq1)
                hash_sq2 = sha256_crypt.hash(sq2)
                hash_sq3 = sha256_crypt.hash(sq3)
                writer.writerow([username, hash_sq1, hash_sq2, hash_sq3])
                # thank user for registering
                flash('Thanks for registering!')
                # redirect to login page
                return redirect('login')
        # flash any error messages at bottom of page
        flash(error)
        return render_template('security_questions.html')
    return render_template('security_questions.html')


if __name__ == "__main__":
    app.run(debug=True)
