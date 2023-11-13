from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session
import pyodbc
import os
import re

load_dotenv()

# Database connection parameters
server = os.environ.get('SERVER')
database = os.environ.get('DATABASE')
username = os.environ.get('UNAME')
password = os.environ.get('PWORD')

print(server, database, username)

# Establish a database connection
connection = pyodbc.connect('DRIVER={SQL Server};SERVER=' + str(server) +
                            ';DATABASE=' + str(database) +
                            ';UID=' + str(username) +
                            ';PWD=' + str(password))

app = Flask(__name__)

app.secret_key = 'your secret key'

@app.route('/')
@app.route('/home')
def home():
    return render_template('templates/home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        user = request.form['username']
        passw = request.form['password']
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM Member WHERE Username = ? AND Password = ?', (user, passw,))
        # we need a stored procedure for loging in
        account = cursor.fetchone()
        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            msg = 'Logged in successfully !'
            return render_template('templates/index.html', msg=msg)
        else:
            msg = 'Incorrect username / password !'
    return render_template('templates/login.html', msg=msg)



@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    cursor = connection.cursor()
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        user = request.form['username']
        pword = request.form['password']
        email = request.form['email']
        role = request.form['role']
        bio = request.form['bio']
        major = request.form['major']
        year = request.form['year']

        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers !'
        elif not user or not pword or not email or not firstname or not lastname or not role or not bio or not major or not year:
            msg = 'Please fill out the form !'
        else:
            cursor.execute("{CALL InsertCabinetMember (?, ?, ?, ?, ?, ?, ?, ?, ?)}", firstname, lastname, user, pword,
                           email, role, bio, major, year)
            cursor.commit()
            msg = 'You have successfully registered !'
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return render_template('templates/register.html', msg=msg)


if __name__ == '__main__':
    app.run()



