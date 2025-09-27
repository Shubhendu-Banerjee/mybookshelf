# app.py (Modifications for my_books route)

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime, timedelta
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'your_secret_key' # IMPORTANT: Change this to a strong, random key in production

DB_FILE = 'books.db'

# --- Flask-Mail Configuration ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com' # e.g., 'smtp.gmail.com' for Gmail
app.config['MAIL_PORT'] = 587 # e.g., 587 for TLS, 465 for SSL
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False # Set to True if using port 465 (SSL)
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') or 'shubhendu.banerjee3107@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') or 'your_email_password' # Use environment variable
mail = Mail(app)

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row # This allows access to columns by name
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL
            );
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS books (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                author TEXT,
                genre TEXT,
                status TEXT NOT NULL,
                current_page INTEGER,
                google_books_id TEXT,
                thumbnail_url TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expiry_time TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        ''')
        conn.commit()

# Initialize the database when the app starts
with app.app_context():
    init_db()

@app.before_request
def require_login():
    # List of routes that do not require login
    allowed_routes = ['login', 'register', 'index', 'static', 'forgot_password', 'reset_password']
    if request.endpoint not in allowed_routes and 'user_id' not in session:
        return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        with get_db_connection() as conn:
            try:
                conn.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                             (username, hashed_password, email))
                conn.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username or Email already exists.', 'danger')
    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        if user:
            token = secrets.token_urlsafe(32)
            expiry_time = datetime.now() + timedelta(hours=1) # Token valid for 1 hour
            
            with get_db_connection() as conn:
                conn.execute('INSERT INTO password_reset_tokens (token, user_id, expiry_time) VALUES (?, ?, ?)',
                             (token, user['id'], expiry_time))
                conn.commit()
            
            reset_link = url_for('reset_password', token=token, _external=True)
            
            msg = Message("Password Reset Request for MyBookShelf",
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])
            msg.body = f"Hello {user['username']},\n\nYou have requested a password reset for your MyBookShelf account. Please click on the following link to reset your password:\n\n{reset_link}\n\nIf you did not request this, please ignore this email.\n\nBest regards,\nMyBookShelf Team"
            
            try:
                mail.send(msg)
                flash('A password reset link has been sent to your email address.', 'info')
            except Exception as e:
                flash(f'Failed to send email. Please try again later. Error: {e}', 'danger')
        else:
            flash('No account found with that email address.', 'danger')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    with get_db_connection() as conn:
        reset_token_data = conn.execute('SELECT user_id, expiry_time FROM password_reset_tokens WHERE token = ?', (token,)).fetchone()

    if not reset_token_data:
        flash('Invalid or expired password reset link.', 'danger')
        return redirect(url_for('login'))
    
    user_id, expiry_time_str = reset_token_data
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

        with get_db_connection() as conn:
            conn.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
            conn.execute("DELETE FROM password_reset_tokens WHERE token = ?", (token,))
            conn.commit()
        
        flash('Your password has been reset successfully. Please log in with your new password.', 'success')
        return redirect(url_for('login'))
        
    return render_template('reset_password.html', token=token)

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')

@app.route('/add', methods=['POST'])
def add_book():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    title = request.form['title']
    author = request.form.get('author')
    genre = request.form.get('genre')
    status = request.form['status']
    current_page = request.form.get('current_page')
    google_books_id = request.form.get('google_books_id')
    thumbnail_url = request.form.get('thumbnail_url')

    if not title:
        flash('Title is required!', 'danger')
        return redirect(url_for('dashboard'))
    
    if status == 'Reading' and (current_page is None or not current_page.isdigit() or int(current_page) < 0):
        flash('Current page must be a non-negative number if status is "Reading".', 'danger')
        return redirect(url_for('dashboard'))
    elif status != 'Reading':
        current_page = 0 # Reset to 0 if not reading

    with get_db_connection() as conn:
        conn.execute('INSERT INTO books (user_id, title, author, genre, status, current_page, google_books_id, thumbnail_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                     (user_id, title, author, genre, status, int(current_page), google_books_id, thumbnail_url))
        conn.commit()
    flash('Book added successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:book_id>')
def delete_book(book_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    with get_db_connection() as conn:
        # Ensure the user owns the book before deleting
        book = conn.execute('SELECT * FROM books WHERE id = ? AND user_id = ?', (book_id, user_id)).fetchone()
        if book:
            conn.execute('DELETE FROM books WHERE id = ?', (book_id,))
            conn.commit()
            flash('Book deleted successfully!', 'success')
        else:
            flash('Book not found or you do not have permission to delete it.', 'danger')
    return redirect(url_for('my_books'))

@app.route('/update_book/<int:book_id>', methods=['POST'])
def update_book(book_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        book = conn.execute('SELECT * FROM books WHERE id = ? AND user_id = ?', (book_id, user_id)).fetchone()
        if not book:
            flash('Book not found or you do not have permission to edit it.', 'danger')
            return redirect(url_for('my_books'))

    status = request.form['status']
    current_page = request.form.get('current_page')

    if status == 'Reading' and (current_page is None or not current_page.isdigit() or int(current_page) < 0):
        flash('Current page must be a non-negative number for "Reading" status.', 'danger')
        return redirect(url_for('my_books'))
    
    if status != 'Reading':
        current_page_val = 0
    else:
        current_page_val = int(current_page)

    with get_db_connection() as conn:
        conn.execute('UPDATE books SET status = ?, current_page = ? WHERE id = ?',
                     (status, current_page_val, book_id))
        conn.commit()
    
    flash('Book updated successfully!', 'success')
    return redirect(url_for('my_books'))

@app.route('/analysis')
def analysis():
    user_id = session.get('user_id')
    if not user_id:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({'error': 'Unauthorized'}), 401
        return redirect(url_for('login'))

    conn = get_db_connection()

    # Genre distribution
    genres = conn.execute(
        'SELECT genre, COUNT(*) as count FROM books WHERE user_id = ? GROUP BY genre',
        (user_id,)
    ).fetchall()

    # Status counts
    status_counts = conn.execute(
        'SELECT status, COUNT(*) as count FROM books WHERE user_id = ? GROUP BY status',
        (user_id,)
    ).fetchall()

    conn.close()

    # Prepare genre data (sort descending by count)
    sorted_genres_list = sorted(
        [{'genre': g['genre'], 'count': g['count']} for g in genres],
        key=lambda x: x['count'],
        reverse=True
    )

    genre_data = {
        'labels': [g['genre'] for g in sorted_genres_list],
        'counts': [g['count'] for g in sorted_genres_list]
    }

    # Status dictionary
    status_dict = {row['status']: row['count'] for row in status_counts}
    total_books = sum(status_dict.values())

    # If AJAX → send only genre data (for chart.js)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(genre_data)

    # Normal request → render stats + chart page
    return render_template(
        'analysis.html',
        total_books=total_books,
        to_read=status_dict.get("To Read", 0),
        reading=status_dict.get("Reading", 0),
        read=status_dict.get("Read", 0),
        genre_data=genre_data
    )

@app.route('/my_books')
@app.route('/my_books/<filter>')
def my_books(filter='all'):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    if filter == 'all':
        books = conn.execute('SELECT * FROM books WHERE user_id = ? ORDER BY title', (user_id,)).fetchall()
    elif filter in ['To Read', 'Reading', 'Read']:
        books = conn.execute('SELECT * FROM books WHERE user_id = ? AND status = ? ORDER BY title', (user_id, filter)).fetchall()
    else:
        flash('Invalid filter option. Showing all books.', 'info')
        books = conn.execute('SELECT * FROM books WHERE user_id = ? ORDER BY title', (user_id,)).fetchall()
    conn.close()

    return render_template('my_books.html', books=books, current_filter=filter)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)