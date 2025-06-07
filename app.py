## MyBookShelf – Full-Stack Web App

# Note: This is a simplified version using Flask + SQLite for ease of understanding and deployment.

# ------------------------
# File: app.py
# ------------------------

from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime, timedelta
from flask_mail import Mail, Message # Added for email functionality

app = Flask(__name__)
app.secret_key = 'your_secret_key' # IMPORTANT: Change this to a strong, random key in production

DB_FILE = 'books.db'

# --- Flask-Mail Configuration ---
# IMPORTANT: Replace these with your actual email server details and credentials.
# For production, consider using environment variables (e.g., os.environ.get('MAIL_USERNAME'))
app.config['MAIL_SERVER'] = 'smtp.gmail.com' # e.g., 'smtp.gmail.com' for Gmail
app.config['MAIL_PORT'] = 587 # e.g., 587 for TLS, 465 for SSL
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False # Set to True if using port 465 (SSL)
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') or 'shubhendu.banerjee3107@gmail.com' # Your actual email
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') or 'ejhy krxf eomn czbd' # Your email password or app password
app.config['MAIL_DEFAULT_SENDER'] = ('MyBookShelf App', app.config['MAIL_USERNAME']) # Sender name and email

mail = Mail(app) # Initialize Flask-Mail

# Initialize database
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT,
                        email TEXT UNIQUE
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS books (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT,
                author TEXT,
                genre TEXT,
                status TEXT,
                progress INTEGER DEFAULT 0,
                google_books_id TEXT,
                thumbnail_url TEXT
            )''')
        c.execute('''CREATE TABLE IF NOT EXISTS password_reset_tokens (
                        token TEXT PRIMARY KEY,
                        user_id INTEGER,
                        expiry_time DATETIME,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )''')
        conn.commit()

init_db()

# ------------------------
# Routes
# ------------------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        with sqlite3.connect(DB_FILE) as conn:
            try:
                conn.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                             (username, hashed_password, email))
                conn.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username or Email already exists.', 'danger')
                return render_template('register.html')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect(DB_FILE) as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DB_FILE) as conn:
        books = conn.execute("SELECT * FROM books WHERE user_id = ?", (session['user_id'],)).fetchall()
    return render_template('dashboard.html', books=books)

@app.route('/add', methods=['POST'])
def add_book():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    title = request.form['title']
    author = request.form['author']
    genre = request.form['genre']
    status = request.form['status']
    current_page = int(request.form.get('current_page', 0))
    google_books_id = request.form.get('google_books_id', None)
    thumbnail_url = request.form.get('thumbnail_url', None)

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            INSERT INTO books (user_id, title, author, genre, status, progress, google_books_id, thumbnail_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], title, author, genre, status, current_page, google_books_id, thumbnail_url))
        conn.commit()

    flash('Book added successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/delete/<int:book_id>')
def delete_book(book_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM books WHERE id = ? AND user_id = ?", (book_id, session['user_id']))
        conn.commit()
    flash('Book deleted successfully.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# --- Forgot Password Routes ---

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        with sqlite3.connect(DB_FILE) as conn:
            user = conn.execute("SELECT id, username FROM users WHERE email = ?", (email,)).fetchone()
        
        if user:
            user_id = user[0]
            token = secrets.token_urlsafe(32)
            expiry_time = datetime.now() + timedelta(hours=1)

            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))
                conn.execute("INSERT INTO password_reset_tokens (token, user_id, expiry_time) VALUES (?, ?, ?)",
                             (token, user_id, expiry_time))
                conn.commit()
            
            reset_link = url_for('reset_password', token=token, _external=True)
            
            # --- EMAIL SENDING VIA FLASK-MAIL ---
            msg = Message("Password Reset Request for MyBookShelf",
                          sender=app.config['MAIL_DEFAULT_SENDER'],
                          recipients=[email])
            msg.body = f"""
Hello {user[1]},

You have requested a password reset for your MyBookShelf account.
Please click on the following link to reset your password:

{reset_link}

This link will expire in 1 hour. If you did not request a password reset, please ignore this email.

Thank You,
MyBookShelf Team
"""
            try:
                mail.send(msg)
                flash('A password reset link has been sent to your email. Please check your inbox.', 'info')
            except Exception as e:
                print(f"Error sending email: {e}") # Log error for debugging
                flash('There was an error sending the password reset email. Please try again later.', 'danger')
            
            return redirect(url_for('login'))
        else:
            flash('If an account with that email exists, a password reset link has been sent to your email.', 'info')
            return render_template('forgot_password.html')

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    with sqlite3.connect(DB_FILE) as conn:
        reset_token = conn.execute("SELECT user_id, expiry_time FROM password_reset_tokens WHERE token = ?", (token,)).fetchone()

    if not reset_token:
        flash('Invalid or expired password reset link.', 'danger')
        return redirect(url_for('login'))
    
    user_id, expiry_time_str = reset_token
    expiry_time = datetime.strptime(expiry_time_str, '%Y-%m-%d %H:%M:%S.%f')

    if datetime.now() > expiry_time:
        flash('Password reset link has expired. Please request a new one.', 'danger')
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("DELETE FROM password_reset_tokens WHERE token = ?", (token,))
            conn.commit()
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)
        
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')

        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
            conn.execute("DELETE FROM password_reset_tokens WHERE token = ?", (token,))
            conn.commit()
        
        flash('Your password has been reset successfully. Please log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

if __name__ == '__main__':
    app.run(debug=True)