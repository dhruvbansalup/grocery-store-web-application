from flask import render_template, request, flash, redirect, url_for, session
from app import app
from models import User, Category, Product, Cart, Transaction, Order
from models import db
from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/')
def index():
    #CHECK IF USER IS LOGGED IN
    if 'user_id' in session:
        return render_template('index.html')
    else:
        flash('Please login to continue')
        return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login',methods=['POST'])
def login_post():
    username=request.form['username']
    password=request.form['password']

    #VALIDATIONS
    if not password or not username:
        flash('Please fill all the fields')
        return redirect(url_for('login'))
    #CHECK IF USER EXISTS
    user=User.query.filter_by(username=username).first()
    if not user:
        flash('Invalid username')
        return redirect(url_for('login'))
    #CHECK PASSWORD
    if not check_password_hash(user.passhash, password):
        flash('Invalid password')
        return redirect(url_for('login'))
    
    #LOGIN SUCCESSFUL
    session['user_id']=user.id
    flash('Login successful')
    return redirect(url_for('index'))

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register',methods=['POST'])
def register_post():
    name= request.form['name']
    username = request.form['username']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    #VALIDATIONS
    if not password or not username or not confirm_password:
        flash('Please fill all the fields')
        return redirect(url_for('register'))
    if password != confirm_password:
        flash('Password & Confirm Password does not match')
        return redirect(url_for('register'))
    
    user=User.query.filter_by(username=username).first()
    if user: #if user already exists
        flash('Username already exists')
        return redirect(url_for('register'))
    
    #HASHING PASSWORD
    passhash=generate_password_hash(password)

    #INSERT INTO DATABASE
    new_user=User(username=username, passhash=passhash, name=name)
    db.session.add(new_user)
    db.session.commit()
    
    flash('User registered successfully with username: '+str(username))
    return redirect(url_for('login'))