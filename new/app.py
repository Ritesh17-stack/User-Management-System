from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import os
import hashlib
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)

# Secret key for session
app.secret_key = 'xyzabc123456'

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Ritesh1234@'  # Change this to your MySQL password
app.config['MYSQL_DB'] = 'user_doc_system'

# Initialize MySQL
mysql = MySQL(app)

# File upload configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'jpg', 'png'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max size

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Helper functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = hash_password(request.form['password'])
        
        # Check if account exists in the database
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s AND password = %s', (email, password))
        user = cursor.fetchone()
        
        if user:
            # Create session data
            session['loggedin'] = True
            session['userid'] = user['userid']
            session['name'] = user['name']
            session['email'] = user['email']
            session['role'] = user['role']
            flash('Logged in successfully!', 'success')
            
            # Redirect based on role
            if user['role'] == 'teacher':
                return redirect(url_for('users'))
            else:
                return redirect(url_for('dashboard'))
        else:
            msg = "Incorrect email or password!"
    
    return render_template('login.html', msg=msg)
@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'name' in request.form and 'password' in request.form and 'email' in request.form:
        # Get form data
        name = request.form['name']
        password = request.form['password']
        email = request.form['email']
        role = request.form['role']
        country = request.form['country']
        
        # Check if account exists
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        account = cursor.fetchone()
        
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', name):
            msg = 'Name must contain only characters and numbers!'
        elif not name or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # Hash the password
            hashed_password = hash_password(password)
            # Insert new user with role and country
            cursor.execute('INSERT INTO users (name, email, password, role, country) VALUES (%s, %s, %s, %s, %s)', 
                          (name, email, hashed_password, role, country))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
            # Redirect to users page
            return redirect(url_for('users'))
            
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
        
    return render_template('register.html', msg=msg)

@app.route('/logout')
def logout():
    # Remove session data
    session.pop('loggedin', None)
    session.pop('userid', None)
    session.pop('name', None)
    session.pop('email', None)
    session.pop('role', None)
    
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    # Check if user is logged in
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    # Get user's documents
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM documents WHERE userid = %s', (session['userid'],))
    documents = cursor.fetchall()
    
    return render_template('dashboard.html', documents=documents)

@app.route('/users')
def users():
    # Check if admin is logged in
    if 'loggedin' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    # Get all users
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    
    return render_template('users.html', users=users)

@app.route('/view/<int:userid>')
def view(userid):
    # Check if user is logged in
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    # Get user details
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE userid = %s', (userid,))
    user = cursor.fetchone()
    
    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('users'))
    
    return render_template('view.html', user=user)

@app.route('/edit/<int:userid>', methods=['GET', 'POST'])
def edit(userid):
    # Check if admin is logged in
    if 'loggedin' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    msg = ''
    # Get user details
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE userid = %s', (userid,))
    editUser = cursor.fetchone()
    
    if not editUser:
        flash('User not found!', 'danger')
        return redirect(url_for('users'))
    
    if request.method == 'POST':
        # Update user details
        name = request.form['name']
        role = request.form['role']
        country = request.form['country']
        
        cursor.execute('UPDATE users SET name = %s, role = %s, country = %s WHERE userid = %s', 
                      (name, role, country, userid))
        mysql.connection.commit()
        
        msg = 'User updated successfully!'
        return redirect(url_for('users'))
    
    return render_template('edit.html', editUser=editUser, msg=msg)

@app.route('/password_change/<int:userid>', methods=['GET', 'POST'])
def password_change(userid):
    # Check if admin is logged in or if user is changing their own password
    if 'loggedin' not in session or (session['role'] != 'admin' and session['userid'] != userid):
        return redirect(url_for('login'))
    
    msg = ''
    changePassUserId = userid
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['password']
        confirm_pass = request.form['confirm_pass']
        
        # Check if current password is correct
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT password FROM users WHERE userid = %s', (userid,))
        account = cursor.fetchone()
        
        if hash_password(current_password) != account['password']:
            msg = 'Current password is incorrect!'
        elif new_password != confirm_pass:
            msg = 'New passwords do not match!'
        else:
            # Update password
            hashed_password = hash_password(new_password)
            cursor.execute('UPDATE users SET password = %s WHERE userid = %s', (hashed_password, userid))
            mysql.connection.commit()
            msg = 'Password changed successfully!'
            
            # If admin changing other user's password, redirect to users page
            if session['userid'] != userid:
                return redirect(url_for('users'))
    
    return render_template('password_change.html', msg=msg, changePassUserId=changePassUserId)

@app.route('/delete/<int:userid>')
def delete(userid):
    # Check if admin is logged in
    if 'loggedin' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    # Delete user
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # First delete related records
    cursor.execute('DELETE FROM documents WHERE userid = %s', (userid,))
    cursor.execute('DELETE FROM grades WHERE userid = %s', (userid,))
    
    # Then delete user
    cursor.execute('DELETE FROM users WHERE userid = %s', (userid,))
    mysql.connection.commit()
    
    flash('User deleted successfully!', 'success')
    return redirect(url_for('users'))

@app.route('/grades')
def grades():
    # Check if user is logged in
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    # Get user's grades if student
    if session['role'] == 'student':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM grades WHERE userid = %s', (session['userid'],))
        grades = cursor.fetchall()
        
        # Calculate average score if grades exist
        average_score = None
        if grades:
            total_score = sum(grade['score'] for grade in grades)
            average_score = round(total_score / len(grades), 2)
            
        return render_template('user_grades.html', grades=grades, average_score=average_score)
    # Show all students and their grades if teacher
    elif session['role'] == 'teacher':
        return redirect(url_for('manage_grades'))
    else:
        return redirect(url_for('dashboard'))

@app.route('/manage_grades', methods=['GET', 'POST'])
def manage_grades():
    # Check if teacher is logged in
    if 'loggedin' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
    
    msg = ''
    # Get all students
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE role = "student"')
    users = cursor.fetchall()
    
    if request.method == 'POST' and 'userid' in request.form:
        userid = request.form['userid']
        subject = request.form['subject']
        grade = request.form['grade']
        score = request.form['score']
        comments = request.form['comments']
        
        # Insert grade
        cursor.execute('INSERT INTO grades (userid, subject, grade, score, comments, grade_date) VALUES (%s, %s, %s, %s, %s, NOW())', 
                     (userid, subject, grade, score, comments))
        mysql.connection.commit()
        
        msg = 'Grade added successfully!'
    
    return render_template('manage_grades.html', users=users, msg=msg)

@app.route('/get_user_grades/<int:userid>')
def get_user_grades(userid):
    # Check if teacher is logged in
    if 'loggedin' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))
    
    # Get user's grades
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM grades WHERE userid = %s', (userid,))
    grades = cursor.fetchall()
    
    # Return as JSON
    return jsonify(grades)

@app.route('/upload_document', methods=['GET', 'POST'])
def upload_document():
    # Check if user is logged in
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    msg = ''
    if request.method == 'POST':
        # Check if file is selected
        if 'file' not in request.files:
            msg = 'No file selected!'
            return render_template('upload_document.html', msg=msg)
            
        file = request.files['file']
        if file.filename == '':
            msg = 'No file selected!'
            return render_template('upload_document.html', msg=msg)
            
        if file and allowed_file(file.filename):
            # Save file
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            unique_filename = f"{timestamp}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
            
            # Save document details to database
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('INSERT INTO documents (userid, filename, originalname, upload_date) VALUES (%s, %s, %s, NOW())', 
                         (session['userid'], unique_filename, filename))
            mysql.connection.commit()
            
            msg = 'Document uploaded successfully!'
            return redirect(url_for('dashboard'))
        else:
            msg = 'Invalid file format! Allowed formats: pdf, doc, docx, txt, jpg, png'
            
    return render_template('upload_document.html', msg=msg)

@app.route('/download/<filename>')
def download_file(filename):
    # Check if user is logged in
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    # Verify user has access to this file (if not admin)
    if session['role'] != 'admin':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM documents WHERE filename = %s AND userid = %s', (filename, session['userid']))
        document = cursor.fetchone()
        if not document:
            flash('Access denied!', 'danger')
            return redirect(url_for('dashboard'))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)