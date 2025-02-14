from flask import render_template, request, flash, redirect, url_for, session, g
from app import app
from models import User, Category, Product, Cart, Transaction, Order
from models import db
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# passing user to the all templates (for navbar)
@app.before_request
def load_user_and_theme():
    g.user = None
    g.theme = 'dark'
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])
    if 'theme' in session:
        g.theme = session['theme']

@app.context_processor
def inject_user_and_theme():
    return dict(user=g.user, theme=g.theme)

@app.route('/toggle_theme',methods=['POST'])
def toggle_theme():
    current_theme = g.theme
    if current_theme == 'light':
        new_theme = 'dark'
    else: 
        new_theme='light'
    session['theme'] = new_theme
    return redirect(request.referrer)

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

# Decorator For Checking if the user is currently login
def auth_required(func):
    @wraps(func)
    def inner(*args,**kwargs):
        if 'user_id' in session:
            return func(*args,**kwargs)
        else:
            flash('Please login to continue')
            return redirect(url_for('login'))
    return inner

@app.route('/')
@auth_required
def index():
    user=User.query.get(session['user_id'])
    if user.is_admin:
        return redirect(url_for('admin'))
    else:
        return render_template('index.html')

@app.route('/profile')
@auth_required
def profile():
    user=User.query.get(session['user_id'])
    return render_template("profile.html")

@app.route('/profile',methods=['POST'])
@auth_required
def profile_post():
    username=request.form.get("username")
    name=request.form.get("name")
    cpassword=request.form.get("cpassword")
    password=request.form.get("password")

     #VALIDATIONS
    if not password or not cpassword or not username:
        flash('Please fill required fields')
        return redirect(url_for('profile'))
    
    user=User.query.get(session['user_id'])

    if not check_password_hash(user.passhash, cpassword):
        flash('Invalid Current password')
        return redirect(url_for('profile'))

    if username!=user.username:
        new_username=User.query.filter_by(username=username).first()
        if new_username:
            flash("Username already exists")
            return redirect(url_for('profile'))
    

    new_pass_hash=generate_password_hash(password)
    user.username=username
    user.passhash=new_pass_hash
    user.name=name
    db.session.commit()
    flash("Profile Updated Successfully!!")
    return redirect(url_for('profile'))


@app.route('/logout')
@auth_required
def logout():
    print(session)
    session.pop('user_id')
    return redirect(url_for('login'))

@app.route("/cart")
@auth_required
def cart():
    return ""

@app.route("/orders")
@auth_required
def orders():
    return "" 

@app.route("/admin")
@auth_required
def admin():
    user=User.query.get(session['user_id'])
    if not user.is_admin:
        flash("You are not authorized to access admin dashboard.")
        return redirect(url_for('index'))
    return render_template('admin.html') 
