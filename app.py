from flask import Flask, render_template, request, redirect, url_for, session
import pyodbc
import re
import datetime

# Database connection parameters
server = ''
database = ''
username = ''
password = ''

print(server, database, username)

# Establish a database connection
connection = pyodbc.connect('DRIVER={SQL Server};SERVER=' + str(server) +
                            ';DATABASE=' + str(database) +
                            ';UID=' + str(username) +
                            ';PWD=' + str(password))

app = Flask(__name__)

app.secret_key = 'your secret key'

#These have to be here because python is stupid

sql = """\
SET NOCOUNT ON;
DECLARE @out nvarchar(max);
EXEC [dbo].[UserLogin] @Username = ?, @Password = ?, @LoginSuccess = @out OUTPUT;
SELECT @out AS the_output;
"""

sql2 = """\
SET NOCOUNT ON;
DECLARE @out nvarchar(max);
EXEC [dbo].[getId] @Username = ?, @PersonID = @out OUTPUT;
SELECT @out AS the_output;
"""

@app.route('/')
@app.route('/home')
def home():
    return render_template('templates/home.html')

@app.route('/notes', methods=['GET', 'POST'])
def notes():
    cursor = connection.cursor()
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        cabinet_member_id = int(str(cursor.execute(sql2, session['username']).fetchone()).replace('\'','').replace('(','').replace(')','').replace(',',''))
        date = request.form['date']
        time = request.form['time']
        notes = request.form['notes']

        # Call the stored procedure to insert meeting note
        print(date,",",time,',',notes,',',cabinet_member_id)
        cursor.execute('{call InsertMeetingNote (?, ?, ?, ?)}', (cabinet_member_id, date, time, notes))
        connection.commit()

    #cursor = connection.cursor()
    #cursor.execute('SELECT [Date], [Time], Notes FROM MeetingNotes WHERE CabinetMemberID = ?', session['id'])
    #meeting_notes = cursor.fetchall()

    # meeting_notes=meeting_notes

    return render_template('templates/notes.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        user = request.form['username']
        passw = request.form['password']
        cursor = connection.cursor()

        # Declare an additional parameter for the output
         # Initialize with a default value
        login_success_param=None

        # Execute the stored procedure with output parameter
        cursor.execute(sql, (user, passw))

        login_success_param = cursor.fetchone()
        # Commit the transaction to make sure the output parameter is populated
        connection.commit()

        # Retrieve the output parameter value
        login_success = str(login_success_param).replace('\'','').replace('(','').replace(')','').replace(',','')
        print(f"Login Attempt - Username: {user}, Password: {passw}, Login Success: {login_success}")

        if int(login_success) == 1:
            # Retrieve other information if needed
            session['loggedin'] = True
            session['username'] = user
            msg = 'Logged in successfully!'
            print(f"Successful Login - Username: {user}")
            return render_template('templates/home.html', msg=msg)
        else:
            msg = 'Incorrect username / password!'
            print(f"Failed Login Attempt - Username: {user}")

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


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'loggedin' in session and session['loggedin']:
        # Retrieve additional user information from the database if needed
        user_info = get_user_info(session['username'])  # Implement this function to fetch user info

        if request.method == 'POST':
            # Update user information or delete account based on the form submission
            action = request.form.get('action')

            if action == 'update':
                # Implement the update logic here, and redirect to the updated profile
                return redirect(url_for('profile'))

            elif action == 'delete':
                # Implement the account deletion logic here
                delete_user_account(session['username'])
                session.clear()
                return redirect(url_for('home'))

        return render_template('templates/profile.html', user_info=user_info)
    else:
        return redirect(url_for('login'))



def get_user_info(username):
    # Assuming your users table has columns: username, email, and other_info
    cursor = connection.cursor()
    query = "SELECT * FROM Person WHERE Username = ?"
    result = cursor.execute(query, (username,)).fetchone()

    if result:
        user_info = {
            'username': result.Username,
            'email': result.Email,
        }
        return user_info
    else:
        return None

def update_user_info(new_data):
    cursor = connection.cursor()
    try:
        # Execute the UpdateCabinetMember stored procedure
        cursor.execute("EXEC [dbo].[UpdateCabinetMember] @Id=?, @FirstName=?, @LastName=?, @Username=?, @Password=?, @Email=?, @Role=?, @Bio=?, @Major=?, @Year=?",
                       new_data.get('id'),
                       new_data.get('first_name'),
                       new_data.get('last_name'),
                       new_data.get('username'),
                       new_data.get('password'),
                       new_data.get('email'),
                       new_data.get('role'),
                       new_data.get('bio'),
                       new_data.get('major'),
                       new_data.get('year')
                       )
        connection.commit()
        return True  # Update successful
    except pyodbc.Error as e:
        print(f"Error updating user info: {e}")
        return False  # Update failed

def delete_user_account(username):
    cursor = connection.cursor()
    try:
        # Execute the DeleteCabinetMember stored procedure
        cursor.execute("{Call DeleteCabinetMember (?)}", username)
        connection.commit()
        return True  # Deletion successful
    except pyodbc.Error as e:
        print(f"Error deleting user account: {e}")
        return False  # Deletion failed





if __name__ == '__main__':
    app.run()



