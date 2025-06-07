## MyBookShelf – Full-Stack Web App

# Note: This is a simplified version using Flask + SQLite for ease of understanding and deployment.

# ------------------------
# File: app.py
# ------------------------

from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key' # IMPORTANT: Change this to a strong, random key in a production environment

DB_FILE = 'books.db'

# Initialize database
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT
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
        password = generate_password_hash(request.form['password'])
        with sqlite3.connect(DB_FILE) as conn:
            try:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                conn.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError: # Catch specific error for unique constraint
                return 'Username already exists. Please choose a different one.'
            except Exception as e:
                return f'An error occurred: {e}' # More general error handling
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
                return redirect(url_for('dashboard'))
            return 'Invalid credentials. Please try again.' # More user-friendly message
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

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
    progress = int(request.form.get('progress', 0))
    google_books_id = request.form.get('google_books_id', None)
    thumbnail_url = request.form.get('thumbnail_url', None)

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            INSERT INTO books (user_id, title, author, genre, status, progress, google_books_id, thumbnail_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], title, author, genre, status, progress, google_books_id, thumbnail_url))
        conn.commit()

    return redirect(url_for('dashboard'))


@app.route('/delete/<int:book_id>')
def delete_book(book_id):
    if 'user_id' not in session: # Ensure user is logged in before deleting
        return redirect(url_for('login'))

    with sqlite3.connect(DB_FILE) as conn:
        # Added user_id to the WHERE clause to prevent users from deleting other users' books
        conn.execute("DELETE FROM books WHERE id = ? AND user_id = ?", (book_id, session['user_id']))
        conn.commit()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)