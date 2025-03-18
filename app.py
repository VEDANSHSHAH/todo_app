import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, g
from flask_session import Session
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

# Initialize Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secure-secret-key')

# Use filesystem sessions locally, Redis on Render if REDIS_URL is provided
if os.getenv('FLASK_ENV') == 'development' or not os.getenv('REDIS_URL'):
    app.config['SESSION_TYPE'] = 'filesystem'
else:
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = os.getenv('REDIS_URL')

app.config['SESSION_KEY_PREFIX'] = 'flask_session:'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') != 'development'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
Session(app)

# Determine base URL based on environment
if os.getenv('FLASK_ENV') == 'development':
    BASE_URL = 'http://127.0.0.1:5000'
else:
    BASE_URL = os.getenv('BASE_URL', 'https://flask-to-do-app-with-oauth.onrender.com')

# Google OAuth configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    redirect_uri=lambda: BASE_URL + '/auth/callback',  # Updated to /auth/callback for Render
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',  # For jwks_uri
    client_kwargs={
        'scope': 'openid profile email',
        'response_type': 'code',
        'flow': 'authorization_code'
    }
)

# Database initialization with persistent disk support
def init_db():
    db_path = os.path.join(os.getenv('DATA_DIR', '.'), 'todo.db')
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute('PRAGMA table_info(users)')
        columns = [row[1] for row in c.fetchall()]
        if 'password' not in columns or not columns:
            c.execute('DROP TABLE IF EXISTS users')
            c.execute('''CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )''')
        c.execute('''CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            completed BOOLEAN NOT NULL DEFAULT 0,
            created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            user_id TEXT NOT NULL
        )''')
        conn.commit()

# Initialize database on app start
init_db()

# Routes
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    user_id = session['user']
    sort_by = request.args.get('sort', 'created')
    sort_order = 'ASC' if sort_by == 'created' else 'DESC'

    try:
        conn = sqlite3.connect(os.path.join(os.getenv('DATA_DIR', '.'), 'todo.db'))
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(f'SELECT * FROM todos WHERE user_id = ? ORDER BY {sort_by} {sort_order}', (user_id,))
        todos = c.fetchall()
        conn.close()
    except Exception as e:
        app.logger.error(f"Database error: {e}")
        abort(500)

    return render_template('todo.html', todos=todos, user=user_id, sort_by=sort_by)

@app.route('/login')
def login():
    if 'user' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/signup')
def signup():
    if 'user' in session:
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/manual_login', methods=['POST'])
def manual_login():
    email = request.form['email']
    password = request.form['password']

    try:
        conn = sqlite3.connect(os.path.join(os.getenv('DATA_DIR', '.'), 'todo.db'))
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user'] = user['email']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
    except Exception as e:
        app.logger.error(f"Database error: {e}")
        abort(500)

@app.route('/manual_signup', methods=['POST'])
def manual_signup():
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    if password != confirm_password:
        flash('Passwords do not match', 'danger')
        return redirect(url_for('signup'))

    try:
        conn = sqlite3.connect(os.path.join(os.getenv('DATA_DIR', '.'), 'todo.db'))
        c = conn.cursor()
        hashed_password = generate_password_hash(password)
        c.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
        conn.commit()
        conn.close()
        flash('Sign-up successful! Please log in.', 'success')
        return redirect(url_for('login'))
    except sqlite3.IntegrityError:
        flash('Email already exists', 'danger')
        return redirect(url_for('signup'))
    except Exception as e:
        app.logger.error(f"Database error: {e}")
        abort(500)

@app.route('/google_login')
def google_login():
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    session['oauth_nonce'] = nonce
    return google.authorize_redirect(redirect_uri=BASE_URL + '/auth/callback', state=state, nonce=nonce)

@app.route('/auth/callback')  # Updated to /auth/callback
def authorize():
    stored_state = session.get('oauth_state')
    received_state = request.args.get('state')
    if not stored_state or stored_state != received_state:
        app.logger.error(f"State mismatch: stored={stored_state}, received={received_state}")
        return "State mismatch error", 403

    stored_nonce = session.get('oauth_nonce')
    token = google.authorize_access_token()
    user = google.parse_id_token(token, nonce=stored_nonce)
    session['user'] = user['email']
    session.pop('oauth_state', None)
    session.pop('oauth_nonce', None)

    try:
        conn = sqlite3.connect(os.path.join(os.getenv('DATA_DIR', '.'), 'todo.db'))
        c = conn.cursor()
        c.execute('INSERT OR IGNORE INTO users (email, password) VALUES (?, ?)', (user['email'], ''))
        conn.commit()
        conn.close()
    except Exception as e:
        app.logger.error(f"Database error: {e}")
        abort(500)

    flash('Logged in with Google successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/', methods=['POST'])
def add_task():
    if 'user' not in session:
        return redirect(url_for('login'))

    content = request.form.get('content')
    if not content:
        return redirect(url_for('index'))

    user_id = session['user']
    try:
        conn = sqlite3.connect(os.path.join(os.getenv('DATA_DIR', '.'), 'todo.db'))
        c = conn.cursor()
        c.execute('INSERT INTO todos (content, user_id) VALUES (?, ?)', (content, user_id))
        conn.commit()
        conn.close()
    except Exception as e:
        app.logger.error(f"Database error: {e}")
        abort(500)

    return redirect(url_for('index'))

@app.route('/delete/<int:id>', methods=['POST'])
def delete(id):
    if 'user' not in session:
        return redirect(url_for('login'))

    user_id = session['user']
    try:
        conn = sqlite3.connect(os.path.join(os.getenv('DATA_DIR', '.'), 'todo.db'))
        c = conn.cursor()
        c.execute('DELETE FROM todos WHERE id = ? AND user_id = ?', (id, user_id))
        conn.commit()
        conn.close()
    except Exception as e:
        app.logger.error(f"Database error: {e}")
        abort(500)

    return redirect(url_for('index'))

@app.route('/update/<int:id>', methods=['POST'])
def update(id):
    if 'user' not in session:
        return redirect(url_for('login'))

    content = request.form.get('content')
    if not content:
        return redirect(url_for('index'))

    user_id = session['user']
    try:
        conn = sqlite3.connect(os.path.join(os.getenv('DATA_DIR', '.'), 'todo.db'))
        c = conn.cursor()
        c.execute('UPDATE todos SET content = ? WHERE id = ? AND user_id = ?', (content, id, user_id))
        conn.commit()
        conn.close()
    except Exception as e:
        app.logger.error(f"Database error: {e}")
        abort(500)

    return redirect(url_for('index'))

@app.route('/completed/<int:id>', methods=['POST'])
def completed(id):
    if 'user' not in session:
        return redirect(url_for('login'))

    user_id = session['user']
    try:
        conn = sqlite3.connect(os.path.join(os.getenv('DATA_DIR', '.'), 'todo.db'))
        c = conn.cursor()
        c.execute('SELECT completed FROM todos WHERE id = ? AND user_id = ?', (id, user_id))
        result = c.fetchone()
        if result:
            completed_status = not result[0]
            c.execute('UPDATE todos SET completed = ? WHERE id = ? AND user_id = ?', (completed_status, id, user_id))
            conn.commit()
        conn.close()
    except Exception as e:
        app.logger.error(f"Database error: {e}")
        abort(500)

    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))