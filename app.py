# app.py

import string
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime, timedelta
from flask_mail import Mail, Message
import requests # IMPORT for Gutendex API
import re # IMPORT for HTML cleaning

app = Flask(__name__)
app.secret_key = 'your_secret_key' # IMPORTANT: Change this to a strong, random key in production

DB_FILE = 'books.db'

# Define a constant for the Google Books API Key (taken from autocomplete.js)
GOOGLE_BOOKS_API_KEY = "AIzaSyDsiDhyDVcP75Lxwdgi5WBxYBPzcXkIKkk" 

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
        # Original Schema with new 'gutenberg_url' added.
        conn.execute('''
            CREATE TABLE IF NOT EXISTS books (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                author TEXT,
                genre TEXT,
                status TEXT NOT NULL,
                current_page INTEGER,
                google_books_id TEXT,       -- Kept for existing autocomplete integration
                thumbnail_url TEXT,
                gutenberg_url TEXT,         -- NEW: For free ebook content URL
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

        conn.execute('''
            CREATE TABLE IF NOT EXISTS dismissed_recommendations (
                user_id INTEGER NOT NULL,
                google_books_id TEXT NOT NULL,
                dismissed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                PRIMARY KEY (user_id, google_books_id)
            );
        ''')
        conn.commit()

# Initialize the database when the app starts
with app.app_context():
    init_db()

def normalize_title(title):
    """Cleans a book title for robust comparison, only making it case-insensitive."""
    if not title:
        return ""
    # 1. Convert to lowercase
    normalized = title.lower()
    # 2. IMPORTANT: Keep punctuation. The old lines for removing punctuation and
    #    extra whitespace are now removed/modified to preserve it.
    
    # We will still ensure there's no excessive whitespace, though.
    # We keep only standard leading/trailing strip and collapsing internal spaces.
    normalized = " ".join(normalized.split())
    return normalized

def get_google_recommendations(genre, user_normalized_titles, user_book_ids):
    """
    Queries Google Books API for a given genre, filters out books the user already owns 
    based on the normalized title, and returns a list of up to 3 unique recommended books.
    
    The user_book_ids set is now used to ensure unique recommendations across different genre searches.
    """
    base_url = "https://www.googleapis.com/books/v1/volumes"
    recommended_books = []
    page = 0
    
    # Try up to 5 pages of search results to ensure we find 3 unique books
    while len(recommended_books) < 3 and page < 5: 
        params = {
            'q': f'subject:"{genre}"',
            'orderBy': 'relevance', 
            'maxResults': 10,
            'startIndex': page * 10,
            'key': GOOGLE_BOOKS_API_KEY
        }
        
        try:
            response = requests.get(base_url, params=params)
            response.raise_for_status() 
            data = response.json()
            
            if 'items' not in data:
                break 
            
            for item in data['items']:
                volume_info = item.get('volumeInfo', {})
                book_id = item.get('id')
                book_title = volume_info.get('title')
                
                # Check for essential data
                if not (book_id and book_title and volume_info.get('authors')):
                    continue
                
                # --- FILTERING LOGIC: Check normalized title ---
                normalized_rec_title = normalize_title(book_title)
                
                # 1. Check if the book's title is already in the user's library
                if normalized_rec_title in user_normalized_titles:
                    continue 
                
                # 2. Check if the book's specific Google Books ID was already recommended 
                #    in a previous genre search to ensure the final list is unique by ID
                if book_id in user_book_ids:
                    continue
                # ----------------------------------------------------
                
                # Construct a book object
                book = {
                    'title': book_title,
                    'author': ', '.join(volume_info['authors']),
                    'thumbnail': volume_info.get('imageLinks', {}).get('smallThumbnail', 'static/images/placeholder.png'),
                    'google_books_id': book_id,
                    'genre': genre
                }
                
                recommended_books.append(book)
                
                # Add the Google Books ID to the set to prevent recommending it again
                user_book_ids.add(book_id)
                
                if len(recommended_books) >= 3:
                    return recommended_books 
            
            page += 1
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching recommendations for genre '{genre}': {e}")
            break

    return recommended_books

@app.before_request
def require_login():
    # UPDATED: Added new routes for the public search/view feature
    allowed_routes = ['login', 'register', 'index', 'static', 'forgot_password', 'reset_password', 
                      'search_public_books', 'api_search_books', 'view_book', 'api_preview_book']
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

@app.route('/logout')
def logout():
    """Logs out the user by clearing the session."""
    # Check if the user is actually logged in
    if 'user_id' in session:
        # Clear specific session variables
        session.pop('user_id', None)
        session.pop('username', None)
        
        # Optional: Clear the entire session if preferred, though usually discouraged
        # session.clear() 
        
        flash('You have been logged out successfully.', 'success')
    
    # Redirect to the login page regardless of whether they were logged in
    return redirect(url_for('login'))

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
        with get_db_connection() as conn:
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
@app.route('/add_book', methods=['POST'])
def add_book():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to add books.', 'danger')
        return redirect(url_for('login'))
    
    title = request.form.get('title', '').strip()
    author = request.form.get('author', 'Unknown Author').strip()
    genre = request.form.get('genre', '').strip()
    status = request.form.get('status', 'To Read').strip()
    current_page = request.form.get('current_page', 0)
    
    # ISOLATED API DATA HANDLING: Handles data from both autocomplete (Google Books) and the new search (Gutendex)
    google_books_id = request.form.get('google_books_id', None) 
    thumbnail_url = request.form.get('thumbnail_url', None)     
    gutenberg_url = request.form.get('gutenberg_url', None)     

    if not title:
        flash('Book title is required.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        current_page = int(current_page)
    except ValueError:
        current_page = 0
        
    try:
        conn = get_db_connection()
        conn.execute(
            '''INSERT INTO books (
                user_id, title, author, genre, status, current_page, 
                google_books_id, thumbnail_url, gutenberg_url
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (user_id, title, author, genre, status, current_page, 
             google_books_id, thumbnail_url, gutenberg_url)
        )
        conn.commit()
        conn.close()
        flash(f'"{title}" by {author} added to your list!', 'success')
    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'danger')

    # Redirect logic: if added from search_public, go to my_books, else dashboard
    if gutenberg_url:
        return redirect(url_for('my_books'))
    return redirect(url_for('dashboard'))


# --- HELPER FUNCTION FOR CONTENT CLEANING ---
def clean_gutenberg_html(html_content):
    """
    Cleans up Project Gutenberg's boilerplate HTML to isolate the book's text.
    """
    # 1. Strip everything before the START marker 
    start_marker_pattern = re.compile(r'\*\*\* START OF (THE PROJECT GUTENBERG EBOOK|THIS PROJECT GUTENBERG EDITION) .*? \*\*\*', re.DOTALL | re.IGNORECASE)
    match_start = start_marker_pattern.search(html_content)
    if match_start:
        html_content = html_content[match_start.end():]

    # 2. Strip everything after the END marker 
    end_marker_pattern = re.compile(r'\*\*\* END OF (THE PROJECT GUTENBERG EBOOK|THIS PROJECT GUTENBERG EDITION) .*? \*\*\*', re.DOTALL | re.IGNORECASE)
    match_end = end_marker_pattern.search(html_content)
    if match_end:
        html_content = html_content[:match_end.start()]
    
    # 3. Aggressive removal of all script/style tags, and unwanted top-level tags
    html_content = re.sub(r'<script\b[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    html_content = re.sub(r'<style\b[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    html_content = re.sub(r'</?(html|body|head|meta|link)\b[^>]*>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    
    return html_content


# --- NEW ROUTES FOR PUBLIC BOOK SEARCH (Gutendex API) ---

@app.route('/search_public_books')
def search_public_books():
    """Renders the free public book search page."""
    if not session.get('user_id'):
        return redirect(url_for('login'))
    return render_template('search_public.html')

@app.route('/api/search_books')
def api_search_books():
    """API endpoint to proxy search requests to the Gutendex API."""
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 401

    query = request.args.get('q')
    if not query:
        return jsonify({'error': 'Search query is missing'}), 400

    GUTENDEX_API_URL = 'https://gutendex.com/books/'

    try:
        params = {
            'search': query,
            'mime_type': 'text/html', # Filter results to only those available in HTML format
            'sort': 'popular',
            'languages': 'en' # Limit to English for better results
        }

        response = requests.get(GUTENDEX_API_URL, params=params)
        response.raise_for_status()
        data = response.json()
        
        books = []
        for item in data.get('results', []):
            
            # Find the direct HTML link
            html_link = item['formats'].get('text/html; charset=utf-8') or item['formats'].get('text/html')
            
            if not html_link:
                continue 
            
            authors = [author['name'] for author in item.get('authors', [])]
            thumbnail_url = item['formats'].get('image/jpeg') 
            
            book = {
                'id': item.get('id'),
                'title': item.get('title'),
                'author': ', '.join(authors) or 'Unknown Author',
                'gutenberg_url': html_link, 
                'thumbnail_url': thumbnail_url,
                'subjects': item.get('subjects', [])
            }
            
            books.append(book)
            
        return jsonify({'success': True, 'books': books})

    except requests.exceptions.RequestException as e:
        return jsonify({'error': 'Failed to connect to the Gutendex API or network error.'}), 500


@app.route('/api/preview_book', methods=['POST'])
def api_preview_book():
    """NEW: Fetches and cleans a snippet of book content for the Preview modal."""
    if not session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 401

    gutenberg_url = request.json.get('gutenberg_url')

    if not gutenberg_url:
        return jsonify({'error': 'Gutenberg URL is required for preview.'}), 400

    try:
        # Fetch the content with a short timeout
        response = requests.get(gutenberg_url, timeout=10)
        response.raise_for_status()
        
        raw_html = response.text
        
        # Clean the HTML content (using existing function)
        cleaned_content = clean_gutenberg_html(raw_html)
        
        # Take the first 4000 characters for a good glimpse
        preview_snippet = cleaned_content[:4000]
        
        # Construct the final HTML snippet with truncation note
        if len(cleaned_content) > 4000:
            preview_html = f"<div class='preview-snippet'>{preview_snippet}... <p class='preview-note'>**Content truncated for preview. Add to your shelf to read the full text.**</p></div>"
        else:
            preview_html = f"<div class='preview-snippet'>{cleaned_content}</div>"

        return jsonify({'success': True, 'content': preview_html})
        
    except requests.exceptions.RequestException:
        return jsonify({'error': 'Could not load book content for preview. The link may be broken or the server timed out.'}), 500


@app.route('/view_book/<int:book_id>')
def view_book(book_id):
    """Fetches the book content from the stored Gutenberg URL and renders it."""
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    book = conn.execute(
        'SELECT id, title, author, gutenberg_url FROM books WHERE id = ? AND user_id = ?',
        (book_id, user_id)
    ).fetchone()
    conn.close()

    if not book:
        flash('Book not found or does not belong to you.', 'danger')
        return redirect(url_for('my_books'))
    
    if not book['gutenberg_url']:
        flash(f"'{book['title']}' does not have a linked Gutenberg HTML page for viewing. Only books added via the 'Search Free Ebooks' feature are viewable.", 'danger')
        return redirect(url_for('my_books'))

    try:
        # Fetch the content with a short timeout
        response = requests.get(book['gutenberg_url'], timeout=15)
        response.raise_for_status()
        
        raw_html = response.text
        
        # Clean the HTML content to remove boilerplate
        cleaned_content = clean_gutenberg_html(raw_html)
        
        return render_template('read_public.html', book=book, content=cleaned_content)
        
    except requests.exceptions.RequestException as e:
        flash(f"Could not load book content from Gutenberg: {e}. The link may be broken or the server timed out.", 'danger')
        return redirect(url_for('my_books'))


@app.route('/update_book/<int:book_id>', methods=['POST'])
def update_book(book_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    title = request.form['title']
    author = request.form.get('author', 'Unknown Author')
    genre = request.form.get('new_genre', '').strip() 
    status = request.form['status']
    current_page = request.form.get('current_page', 0)
    
    if not title:
        flash('Book title cannot be empty.', 'danger')
        return redirect(url_for('my_books'))
    
    try:
        current_page = int(current_page)
    except ValueError:
        flash('Current page must be a number.', 'danger')
        return redirect(url_for('my_books'))
    
    conn = get_db_connection()
    existing_book = conn.execute('SELECT * FROM books WHERE id = ? AND user_id = ?', (book_id, user_id)).fetchone()
    
    if not existing_book:
        conn.close()
        flash('Book not found or unauthorized.', 'danger')
        return redirect(url_for('my_books'))
    
    try:
        conn.execute('''
            UPDATE books
            SET title = ?, author = ?, genre = ?, status = ?, current_page = ?
            WHERE id = ? AND user_id = ?
        ''', (title, author, genre, status, current_page, book_id, user_id))
        conn.commit()
        flash(f'"{title}" updated successfully!', 'success')
    except Exception as e:
        flash(f'An error occurred during update: {e}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('my_books', filter=status))

@app.route('/delete_book/<int:book_id>', methods=['POST'])
def delete_book(book_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    conn = get_db_connection()
    
    book = conn.execute('SELECT title FROM books WHERE id = ? AND user_id = ?', (book_id, user_id)).fetchone()
    
    if book:
        conn.execute('DELETE FROM books WHERE id = ? AND user_id = ?', (book_id, user_id))
        conn.commit()
        flash(f'"{book["title"]}" removed successfully.', 'success')
    else:
        flash('Book not found or unauthorized.', 'danger')
        
    conn.close()
    return redirect(url_for('my_books'))

@app.route('/api/analysis')
def api_analysis():
    user_id = session.get('user_id')
    if not user_id:
        # Prevent unauthorized access, especially to the analysis route
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({'error': 'Unauthorized'}), 401
        return redirect(url_for('login'))

    conn = get_db_connection()

    # -- 1. Fetch dismissed books (google_books_id) for the user --
    dismissed_books_rows = conn.execute(
        'SELECT google_books_id FROM dismissed_recommendations WHERE user_id = ?', 
        (user_id,)
    ).fetchall()
    
    # Convert to a set for efficient lookup
    dismissed_ids = {row['google_books_id'] for row in dismissed_books_rows}

    # --- 2. Get Status Counts (Existing Logic) ---
    status_rows = conn.execute('''
        SELECT status, COUNT(id) as count FROM books WHERE user_id = ? GROUP BY status
    ''', (user_id,)).fetchall()
    
    total_books = 0
    status_dict = {}
    for row in status_rows:
        status_dict[row['status']] = row['count']
        total_books += row['count']

    # --- 3. Get Genre Counts (Existing Logic, slightly enhanced for multi-genre) ---
    genre_rows = conn.execute('''
        SELECT 
            genre, 
            COUNT(id) as count 
        FROM books 
        WHERE 
            user_id = ? AND genre IS NOT NULL AND genre != '' 
        GROUP BY genre
        ORDER BY count DESC
    ''', (user_id,)).fetchall()
    
    genre_counts = {}
    for row in genre_rows:
        genre_string = row['genre'].strip() 
        if genre_string:
            # Only split by commas (,) or semicolons (;) 
            # This preserves multi-word genres like 'Personal Finance' as a single entry.
            genres = re.split(r'[;,]', genre_string) 
            
            for g in genres:
                g = g.strip() # Remove leading/trailing whitespace from the resulting genre
                if g:
                    # Standardize case for accurate counting (e.g., 'fiction' and 'Fiction' count as one)
                    g_title = g.title() 
                    genre_counts[g_title] = genre_counts.get(g_title, 0) + row['count']
    
    # Sort genres by count in descending order
    sorted_genres = sorted(genre_counts.items(), key=lambda item: item[1], reverse=True)
    
    # Get top 3 genres
    top_three_genres = [genre[0] for genre in sorted_genres[:3]]

    # --- 4. Get User's Existing Google Books IDs (For filtering recommendations) ---
    existing_books = conn.execute(
        'SELECT title, google_books_id FROM books WHERE user_id = ?',
        (user_id,)
    ).fetchall()
    
    # Create a set of normalized titles for fast lookup
    user_normalized_titles = set()
    # Create a set of google_books_ids to prevent recommending the SAME book (by ID) 
    # even if it was added under a slightly different title
    user_book_ids = set() 
    
    for row in existing_books:
        user_normalized_titles.add(normalize_title(row['title']))
        if row['google_books_id']:
            user_book_ids.add(row['google_books_id'])

    # --- 5. Get Recommendations ---
    recommendations = []
    # user_book_ids is passed and updated inside the function to track IDs already recommended
    for genre in top_three_genres:
        recs = get_google_recommendations(genre, user_normalized_titles, user_book_ids)
        recommendations.extend(recs)

    filtered_recommendations = [
        book for book in recommendations 
        if book['google_books_id'] not in dismissed_ids
    ]
    
    # Prepare final data
    genre_data = {
        "labels": list(genre_counts.keys()),
        "counts": list(genre_counts.values())
    }
    
    # Handle AJAX request separately (for Chart.js data)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(genre_data)

    # Render template with all data
    return render_template(
        'analysis.html',
        total_books=total_books,
        to_read=status_dict.get("To Read", 0),
        reading=status_dict.get("Reading", 0),
        read=status_dict.get("Read", 0),
        genre_data=genre_data,
        recommendations=filtered_recommendations # NEW: Pass filtered recommendations list
    )

@app.route('/recommendation-action', methods=['POST'])
def recommendation_action():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'success': False, 'message': 'User not logged in.'}), 401

    data = request.get_json()
    google_books_id = data.get('google_books_id')
    action = data.get('action')
    title = data.get('title', 'Unknown Book')

    if not google_books_id or not action:
        return jsonify({'success': False, 'message': 'Missing data.'}), 400

    conn = get_db_connection()
    message = ""
    success = False

    try:
        if action == 'add':
            author = data.get('author')
            genre = data.get('genre')
            thumbnail_url = data.get('thumbnail_url')

            # Check if the book already exists, then insert if not.
            existing_book = conn.execute(
                'SELECT id FROM books WHERE user_id = ? AND google_books_id = ?', 
                (user_id, google_books_id)
            ).fetchone()

            if existing_book:
                message = f"'{title}' is already on your shelf."
            else:
                # UPDATED: Include author and genre in the INSERT statement
                conn.execute(
                    '''INSERT INTO books 
                        (user_id, google_books_id, title, author, genre, thumbnail_url, status) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (user_id, google_books_id, title, author, genre, thumbnail_url, 'To Read')
                )
                # If a book is added, remove it from dismissed_recommendations
                conn.execute(
                    'DELETE FROM dismissed_recommendations WHERE user_id = ? AND google_books_id = ?',
                    (user_id, google_books_id)
                )
                message = f"'{title}' added to your 'To Read' shelf!"
            
            success = True

        elif action == 'dismiss':
            # Record the dismissal persistently
            conn.execute(
                '''
                INSERT OR IGNORE INTO dismissed_recommendations (user_id, google_books_id) 
                VALUES (?, ?)
                ''',
                (user_id, google_books_id)
            )
            message = f"'{title}' dismissed. You won't see this recommendation again."
            success = True

        else:
            message = 'Invalid action.'
            success = False

        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        message = f"Database error: {e}"
        success = False
    finally:
        conn.close()

    return jsonify({'success': success, 'message': message})

@app.route('/analysis')
def analysis():
    return api_analysis()

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

if __name__ == '__main__':
    app.run(debug=True)