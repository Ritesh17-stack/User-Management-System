from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import hashlib
from config import Config  

app = Flask(__name__)

# Load configuration from config.py
app.config.from_object(Config)

# Initialize MySQL with the app
mysql = MySQL(app)

# Helper function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Routes
@app.route('/dashboard')
def dashboard():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE userid = %s', (session['userid'],))
        user = cursor.fetchone()
        return render_template('dashboard.html', user=user)
    return redirect(url_for('login'))

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = hash_password(request.form['password'])
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s AND password = %s', (email, password))
        user = cursor.fetchone()
        if user:
            session['loggedin'] = True
            session['userid'] = user['userid']
            session['name'] = user['name']
            session['email'] = user['email']
            session['role'] = user['role']
            msg = 'Logged in successfully!'
            return redirect(url_for('dashboard'))
        else:
            msg = "Please enter correct email and password!"
    return render_template('login.html', msg=msg)

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('userid', None)
    session.pop('name', None)
    session.pop('email', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/users', methods=['GET', 'POST'])
def users():
    if 'loggedin' in session:
        if session['role'] == 'admin':
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM users')
            users = cursor.fetchall()
            return render_template('users.html', users=users)
        else:
            return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/view', methods=['GET', 'POST'])
def view():
    if 'loggedin' in session:
        viewUserId = request.args.get('userid')
        if str(session['userid']) != str(viewUserId) and session['role'] != 'admin':
            return redirect(url_for('dashboard'))
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE userid = %s', (viewUserId,))
        user = cursor.fetchone()
        return render_template('view.html', user=user)
    return redirect(url_for('login'))

@app.route('/password_change', methods=['GET', 'POST'])
def password_change():
    msg = ''
    if 'loggedin' in session:
        changePassUserId = request.args.get('userid')
        if str(session['userid']) != str(changePassUserId) and session.get('role') != 'admin':
            return redirect(url_for('dashboard'))
        if request.method == 'POST' and 'current_password' in request.form and 'password' in request.form and "confirm_pass" in request.form and "userid" in request.form:
            current_password = request.form['current_password']
            password = request.form['password']
            confirm_pass = request.form['confirm_pass']
            userId = request.form['userid']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            hashed_current_password = hash_password(current_password)
            cursor.execute('SELECT * FROM users WHERE userid = %s AND password = %s', (userId, hashed_current_password))
            account = cursor.fetchone()
            if not account:
                msg = 'Current password is incorrect!'
            elif not password or not confirm_pass:
                msg = 'Please fill out the form!'
            elif password != confirm_pass:
                msg = 'Confirm password is not matching!'
            else:
                hashed_password = hash_password(password)
                cursor.execute('UPDATE users SET password = %s WHERE userid = %s', (hashed_password, userId))
                mysql.connection.commit()
                msg = 'Password updated successfully!'
        elif request.method == 'POST':
            msg = 'Please fill out the form!'
        return render_template('password_change.html', msg=msg, changePassUserId=changePassUserId)
    return redirect(url_for('login'))

@app.route('/edit', methods=['GET', 'POST'])
def edit():
    msg = ''
    if 'loggedin' in session:
        editUserId = request.args.get('userid')
        if str(session['userid']) != str(editUserId) and session['role'] != 'admin':
            return redirect(url_for('dashboard'))
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE userid = %s', (editUserId,))
        editUser = cursor.fetchone()
        if request.method == "POST" and 'name' in request.form and 'userid' in request.form and 'role' in request.form and 'country' in request.form:
            userName = request.form['name']
            role = request.form['role']
            country = request.form['country']
            userid = request.form['userid']
            if not re.match(r'[A-Za-z0-9]+', userName):
                msg = 'Name must contain only characters and numbers!'
            else:
                if session['role'] != 'admin':
                    cursor.execute('UPDATE users SET name = %s, country = %s WHERE userid = %s', 
                                 (userName, country, userid))
                else:
                    cursor.execute('UPDATE users SET name = %s, role = %s, country = %s WHERE userid = %s', 
                                 (userName, role, country, userid))
                mysql.connection.commit()
                msg = 'User updated successfully!'
                return redirect(url_for('dashboard'))
        elif request.method == 'POST':
            msg = 'Please fill out the form!'
        return render_template('edit.html', msg=msg, editUser=editUser)
    return redirect(url_for('login'))

@app.route('/delete', methods=['GET'])
def delete():
    if 'loggedin' in session and session['role'] == 'admin':
        deleteUserId = request.args.get('userid')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('DELETE FROM users WHERE userid = %s', (deleteUserId,))
        mysql.connection.commit()
        return redirect(url_for('users'))
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'name' in request.form and 'password' in request.form and 'email' in request.form:
        userName = request.form['name']
        password = request.form['password']
        email = request.form['email']
        role = request.form['role']
        country = request.form['country']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        account = cursor.fetchone()
        if account:
            msg = 'User already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not userName or not password or not email:
            msg = 'Please fill out the form!'
        else:
            hashed_password = hash_password(password)
            cursor.execute('INSERT INTO users VALUES (NULL, %s, %s, %s, %s, %s, NULL)', 
                          (userName, email, hashed_password, role, country))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)

@app.route('/update_grade', methods=['GET', 'POST'])
def update_grade():
    if 'loggedin' in session and session['role'] == 'admin':
        user_id = request.args.get('userid')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        if request.method == 'POST':
            grade = request.form['grade']
            cursor.execute('UPDATE users SET grade = %s WHERE userid = %s', (grade, user_id))
            mysql.connection.commit()
            return redirect(url_for('users'))
        cursor.execute('SELECT * FROM users WHERE userid = %s', (user_id,))
        user = cursor.fetchone()
        return render_template('update_grade.html', user=user)
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)