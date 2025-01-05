from flask import Flask, request, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import hashlib
import pyotp
import qrcode
import io
import base64
import re

app = Flask(__name__)
app.secret_key = 'FYJqNgdDmOYrIsibvdiqSTkSRPucpbIKSHwaX'  # Set a secret key for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(80), nullable=False)
    key = db.Column(db.String(128), nullable=False)

# Create the database and tables
with app.app_context():
    db.create_all()

# Fuction for creating totp
def create_totp(key):
    totp = pyotp.TOTP(key)
    return totp

@app.route('/')
def home():
    return render_template('home.html')  # Home page with login and signup options

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    message = ''
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            message = "Account with this username already exists."
            return render_template('signup.html', message=message)


        # Hash the password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        key_trial = "JqNgTkSRPucpbIKSHwaX"+password_hash+username
        key=re.sub('[^a-zA-Z]','',key_trial)
        
        # Store the username, email, key, and hashed password in the database
        new_user = User(username=username, password_hash=password_hash, email=email, key=key)
        
        db.session.add(new_user)
        db.session.commit()
        
        user = User.query.filter_by(username=username).first()
        key = user.key
        
        totp = create_totp(key=key)

        # Generate and show QR code
        qr_code = qrcode.make(totp.provisioning_uri(name=username, issuer_name="ProjectMFA"))
        buffered = io.BytesIO()
        qr_code.save(buffered, format="PNG")
        qr_code_uri = base64.b64encode(buffered.getvalue()).decode('utf-8')

        session['is_signing_up'] = True  # Set a flag for sign-up
        session['username'] = username  # Store the username for sign-up
        return render_template('qr_code.html', qr_code_uri='data:image/png;base64,' + qr_code_uri)

    return render_template('signup.html', message=message)

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the entered password
        entered_password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Check if the user exists and the password matches
        user = User.query.filter_by(username=username).first()
        if user and user.password_hash == entered_password_hash:
            session['logged_in'] = True
            session['username'] = username  # Store the username in the session
            return redirect(url_for('enter_totp'))  # Redirect to TOTP entry
        else:
            message = "Invalid username or password."

    return render_template('login.html', message=message)

@app.route('/enter_totp', methods=['GET', 'POST'])
def enter_totp():
    if 'logged_in' not in session and 'is_signing_up' not in session:
        return redirect(url_for('login'))

    message = ''
    if request.method == 'POST':
        code = request.form.get('totp')
        username = session['username']
        user = User.query.filter_by(username=username).first()
        key = user.key
        totp = create_totp(key=key)
        if code:
            if totp.verify(code):
                if 'is_signing_up' in session:
                    session.pop('username')
                    session.pop('is_signing_up', None)
                    return render_template('account_created.html', username=username)
                elif 'logged_in' in session:
                    username = session.get('username')
                    user = User.query.filter_by(username=username).first()
                    if user:
                        return render_template('user_secret.html', username=username, email=user.email)
                    else:
                        message = "User not found."
            else:
                message = "Invalid code. Please try again."
        else:
            message = "TOTP code is missing."

    return render_template('enter_totp.html', message=message)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)