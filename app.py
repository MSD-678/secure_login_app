from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)

# SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # for "Remember Me"
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    if 'user' in session:
        return render_template('index.html', username=session['user'])
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash("User already exists!", "error")
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user'] = username
            session.permanent = True if remember else False
            flash("Login successful!", "success")
            return redirect(url_for('index'))
        flash("Invalid credentials!", "error")
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("👋 You have been logged out.", "success")
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
