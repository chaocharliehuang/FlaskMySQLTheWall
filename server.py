from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import re
import md5
import os, binascii

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

app = Flask(__name__)
app.secret_key = 'secret'
mysql = MySQLConnector(app, 'thewalldb')

@app.route('/')
def index():
    if 'user_id' not in session:
        session['user_id'] = None
    if 'first_name' not in session:
        session['first_name'] = ''
    if 'last_name' not in session:
        session['last_name'] = ''
    if 'email' not in session:
        session['email'] = ''
    if 'login_email' not in session:
        session['login_email'] = ''
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    pw = request.form['pw']
    session['login_email'] = email

    # FORM VALIDATION
    if len(email) < 1 or len(pw) < 1:
        flash('Email and/or password fields cannot be empty!')
        return redirect('/')

    # LOGIN VALIDATION
    data = {
        'email': email,
        'password': pw
    }
    query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    user = mysql.query_db(query, data)
    if len(user) != 0:
        hashed_pw = md5.new(pw + user[0]['salt']).hexdigest()
        if user[0]['password'] == hashed_pw:
            session['user_id'] = str(user[0]['id'])
            session['login_email'] = ''
            return redirect('/wall')
        else:
            flash('Password incorrect!')
            return redirect('/')
    else:
        flash('No user with that email address exists!')
        return redirect('/')

@app.route('/register', methods=['POST'])
def register():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    pw = request.form['pw']
    pw_confirm = request.form['pw_confirm']

    # FORM VALIDATION
    session['first_name'] = first_name
    session['last_name'] = last_name
    session['email'] = email

    if len(first_name) < 2 or len(last_name) < 2 or not first_name.isalpha() or not last_name.isalpha():
        flash('First and last names must be at least 2 characters and only contain letters!')
        return redirect('/')

    if len(email) < 1:
        flash('Email cannot be blank!')
        return redirect('/')
    elif not EMAIL_REGEX.match(email):
        flash('Invalid email address!')
        return redirect('/')

    if len(pw) < 8:
        flash('Password must be at least 8 characters')
        return redirect('/')

    if pw != pw_confirm:
        flash('Passwords don\'t match!')
        return redirect('/')

    session['first_name'] = ''
    session['last_name'] = ''
    session['email'] = ''

    # ADD TO DATABASE
    salt = binascii.b2a_hex(os.urandom(15))
    hashed_pw = md5.new(pw + salt).hexdigest()

    query_data = {
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'password': hashed_pw,
        'salt': salt
    }
    insert_query = "INSERT INTO users (first_name, last_name, email, password, salt, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, :salt, NOW(), NOW())"
    user_id = mysql.query_db(insert_query, query_data)

    session['user_id'] = user_id
    return redirect('/wall')

@app.route('/wall')
def display_wall():
    if session['user_id'] is None:
        return render_template('404.html')

    # DISPLAY LOGGED IN USER'S FIRST NAME IN HEADER
    user_data = {'id': session['user_id']}
    user_query = "SELECT * FROM users WHERE id = :id LIMIT 1"
    user = mysql.query_db(user_query, user_data)

    # DISPLAY ALL MESSAGES ON THE WALL
    messages_query = "SELECT CONCAT_WS(' ', users.first_name, users.last_name) AS user, DATE_FORMAT(messages.created_at, '%M %D, %Y %l:%i %p') AS date, messages.message, messages.id FROM messages JOIN users ON messages.user_id = users.id ORDER BY messages.created_at DESC"
    messages = mysql.query_db(messages_query)

    # DISPLAY ALL COMMENTS ON EACH MESSAGE ON THE WALL
    for message in messages:
        comments_data = {'message_id': message['id']}
        comments_query = "SELECT CONCAT_WS(' ', users.first_name, users.last_name) AS user, DATE_FORMAT(comments.created_at, '%M %D, %Y %l:%i %p') AS date, comments.comment FROM messages JOIN comments on messages.id = comments.message_id JOIN users ON comments.user_id = users.id WHERE messages.id = :message_id ORDER BY comments.created_at ASC"
        message['comments'] = mysql.query_db(comments_query, comments_data)

    return render_template('wall.html', first_name=user[0]['first_name'], messages=messages)

@app.route('/post_message', methods=['POST'])
def post_message():
    message = request.form['message']
    if len(message) < 1:
        flash('Message cannot be empty!')
        return redirect('/wall')
    query_data = {
        'user_id': session['user_id'],
        'message': message
    }
    insert_query = "INSERT INTO messages (user_id, message, created_at, updated_at) VALUES (:user_id, :message, NOW(), NOW())"
    mysql.query_db(insert_query, query_data)
    return redirect('/wall')

@app.route('/post_comment', methods=['POST'])
def post_comment():
    message_id = int(request.form['message_id'])
    comment = request.form['comment']
    if len(comment) < 1:
        flash('Comment cannot be empty!')
        return redirect('/wall')
    query_data = {
        'message_id': message_id,
        'user_id': session['user_id'],
        'comment': comment
    }
    insert_query = "INSERT INTO comments (message_id, user_id, comment, created_at, updated_at) VALUES (:message_id, :user_id, :comment, NOW(), NOW())"
    mysql.query_db(insert_query, query_data)
    return redirect('/wall')

@app.route('/logoff')
def logoff():
    session['user_id'] = None
    return redirect('/')

app.run(debug=True)