import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
load_dotenv()

# Debug: Print loaded environment variables to confirm
print("Loaded environment variables:")
print(f"EMAIL_USER: {os.getenv('EMAIL_USER')}")
print(f"EMAIL_PASSWORD: {os.getenv('EMAIL_PASSWORD')}")
print(f"GOOGLE_CLIENT_ID: {os.getenv('GOOGLE_CLIENT_ID')}")
print(f"GOOGLE_CLIENT_SECRET: {os.getenv('GOOGLE_CLIENT_SECRET')}")
print(f"SECRET_KEY: {os.getenv('SECRET_KEY')}")

# Enable insecure transport for local development (remove in production)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret_key')
app.config['DATABASE'] = 'todo.db'
app.config['EMAIL_USER'] = os.getenv('EMAIL_USER')
app.config['EMAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD')

# Debug: Print app config to confirm values
print("\nApp config after loading environment variables:")
print(f"app.config['EMAIL_USER']: {app.config['EMAIL_USER']}")
print(f"app.config['EMAIL_PASSWORD']: {app.config['EMAIL_PASSWORD']}")

# Configure session settings for OAuth state persistence
app.config['PERMANENT_SESSION_LIFETIME'] = 3600
app.config['SESSION_COOKIE_DOMAIN'] = None
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # False for local dev (no HTTPS)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database connection management
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# User model for Flask-Login
class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
    return User(user['id'], user['email']) if user else None

# Email sending function with enhanced debugging
def send_email(subject, body, recipient=None):
    if not app.config['EMAIL_USER'] or not app.config['EMAIL_PASSWORD']:
        print("⚠️ Email credentials missing! Skipping email.")
        print(f"EMAIL_USER: {app.config['EMAIL_USER']}")
        print(f"EMAIL_PASSWORD: {app.config['EMAIL_PASSWORD']}")
        print("Please check EMAIL_USER and EMAIL_PASSWORD in your .env file.")
        return False
    
    recipient = recipient or current_user.email
    if not recipient:
        print("⚠️ No recipient email available! Ensure user is authenticated.")
        return False
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = app.config['EMAIL_USER']
    msg['To'] = recipient
    
    try:
        print(f"Connecting to SMTP server: smtp.gmail.com:587")
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.set_debuglevel(1)  # Enable SMTP debug output
        print("Starting TLS...")
        server.starttls()
        print(f"Attempting to log in to SMTP with user: {app.config['EMAIL_USER']}")
        print(f"Using EMAIL_PASSWORD: {app.config['EMAIL_PASSWORD']}")  # Debug: Print the password being used
        server.login(app.config['EMAIL_USER'], app.config['EMAIL_PASSWORD'])
        print(f"Sending email to: {recipient}")
        server.send_message(msg)
        server.quit()
        print("✅ Email sent successfully to", recipient)
        return True
    except smtplib.SMTPAuthenticationError as auth_error:
        print("⚠️ Email sending failed: Authentication error.")
        print(f"Error details: {str(auth_error)}")
        print("Check EMAIL_PASSWORD (use an App Password if 2FA is enabled).")
        return False
    except smtplib.SMTPException as smtp_error:
        print("⚠️ Email sending failed: SMTP error.")
        print(f"Error details: {str(smtp_error)}")
        return False
    except Exception as e:
        print("⚠️ Email sending failed: Unexpected error.")
        print(f"Error details: {str(e)}")
        return False

# Google OAuth Configuration
CLIENT_CONFIG = {
    "web": {
        "client_id": os.getenv('GOOGLE_CLIENT_ID'),
        "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": ["http://127.0.0.1:5000/login/callback"]
    }
}

# Routes
@app.route('/', methods=['GET'])
def index():
    if current_user.is_authenticated and 'user_id' in session:
        return redirect(url_for('todo'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated and 'user_id' in session:
        return redirect(url_for('todo'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash("Email and password are required.", "warning")
            return redirect(url_for('login'))
        
        db = get_db()
        user = db.execute("SELECT * FROM user WHERE email = ?", (email,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            login_user(User(user['id'], user['email']))
            session['user_id'] = user['id']
            flash("Logged in successfully!", "success")
            return redirect(url_for('todo'))
        else:
            flash("Invalid email or password.", "danger")
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash("Email and password are required.", "warning")
            return redirect(url_for('register'))
        
        db = get_db()
        existing_user = db.execute("SELECT * FROM user WHERE email = ?", (email,)).fetchone()
        if existing_user:
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for('login'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        db.execute("INSERT INTO user (email, password) VALUES (?, ?)", (email, hashed_password))
        db.commit()
        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/google-login', methods=['GET'])
def google_login():
    print(f"Request URL: {request.url}")
    print(f"Request Referrer: {request.referrer}")
    print(f"Request Headers: {request.headers}")
    print(f"Request Query Params: {request.args.to_dict()}")
    
    session.clear()
    session.permanent = True
    
    client_id = os.getenv('GOOGLE_CLIENT_ID')
    client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
    if not client_id or not client_secret:
        print("⚠️ Google OAuth credentials missing! Check GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env.")
        flash("Google Sign-In is unavailable due to configuration issues.", "danger")
        return redirect(url_for('login'))
    
    try:
        flow = Flow.from_client_config(
            CLIENT_CONFIG,
            scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'],
            redirect_uri='http://127.0.0.1:5000/login/callback'
        )
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent',
            state=session.get('state', None)
        )
        session['state'] = state
        print(f"Stored state in session: {state}")
        print(f"Client ID used: {client_id}")
        print(f"Redirect URI: http://127.0.0.1:5000/login/callback")
        print(f"Redirecting to Google OAuth URL: {authorization_url}")
        return redirect(authorization_url)
    except Exception as e:
        print(f"⚠️ Error initiating Google OAuth flow: {str(e)}")
        flash("Failed to initiate Google Sign-In. Please try again or contact support.", "danger")
        return redirect(url_for('login'))

@app.route('/login/callback', methods=['GET'])
def callback():
    flow = Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'],
        redirect_uri='http://127.0.0.1:5000/login/callback'
    )
    received_state = request.args.get('state')
    stored_state = session.get('state')
    print(f"Received state from Google: {received_state}")
    print(f"Stored state in session: {stored_state}")
    if received_state != stored_state:
        print("State mismatch detected!")
        session.clear()
        flash("Authentication error: State mismatch.", "danger")
        return "State mismatch error", 403
    
    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        print(f"Error during token exchange: {str(e)}")
        session.clear()
        flash(f"Authentication failed: {str(e)}", "danger")
        return redirect(url_for('login'))
    
    credentials = flow.credentials
    service = build('oauth2', 'v2', credentials=credentials)
    user_info = service.userinfo().get().execute()
    email = user_info.get('email')
    if not email:
        print("No email found in Google user info!")
        session.clear()
        flash("Authentication failed: No email provided by Google.", "danger")
        return redirect(url_for('login'))
    
    db = get_db()
    user = db.execute("SELECT * FROM user WHERE email = ?", (email,)).fetchone()
    if not user:
        db.execute("INSERT INTO user (email, password) VALUES (?, ?)", (email, ''))
        db.commit()
        user = db.execute("SELECT * FROM user WHERE email = ?", (email,)).fetchone()
    
    login_user(User(user['id'], user['email']))
    session['user_id'] = user['id']
    print(f"User {email} logged in successfully via Google.")
    return redirect(url_for('todo'))

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('index'))

@app.route('/todo', methods=['GET', 'POST'])
@login_required
def todo():
    db = get_db()
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            db.execute("INSERT INTO task (content, user_id) VALUES (?, ?)", (content, current_user.id))
            db.commit()
            if not send_email("Task Added", f"New task: {content}"):
                flash("Email notification failed. Check server logs.", "warning")
            else:
                flash("Task added successfully!", "success")
        return redirect(url_for('todo'))
    tasks = db.execute("SELECT * FROM task WHERE user_id = ?", (current_user.id,)).fetchall()
    return render_template('todo.html', tasks=tasks)

@app.route('/update/<int:task_id>', methods=['POST'])
@login_required
def update(task_id):
    db = get_db()
    task = db.execute("SELECT * FROM task WHERE id = ? AND user_id = ?", (task_id, current_user.id)).fetchone()
    if not task:
        flash("Task not found or unauthorized.", "warning")
        return redirect(url_for('todo'))
    new_completed = 1 if task['completed'] == 0 else 0
    db.execute("UPDATE task SET completed = ? WHERE id = ?", (new_completed, task_id))
    db.commit()
    if not send_email("Task Updated", f"Task '{task['content']}' marked as {'completed' if new_completed else 'incomplete'}"):
        flash("Email notification failed. Check server logs.", "warning")
    else:
        flash("Task updated successfully!", "success")
    return redirect(url_for('todo'))

@app.route('/delete/<int:task_id>', methods=['POST'])
@login_required
def delete(task_id):
    db = get_db()
    task = db.execute("SELECT * FROM task WHERE id = ? AND user_id = ?", (task_id, current_user.id)).fetchone()
    if not task:
        flash("Task not found or unauthorized.", "warning")
        return redirect(url_for('todo'))
    content = task['content']
    db.execute("DELETE FROM task WHERE id = ?", (task_id,))
    db.commit()
    if not send_email("Task Deleted", f"Task '{content}' deleted"):
        flash("Email notification failed. Check server logs.", "warning")
    else:
        flash("Task deleted successfully!", "success")
    return redirect(url_for('todo'))

@app.route('/edit/<int:task_id>', methods=['POST'])
@login_required
def edit(task_id):
    db = get_db()
    task = db.execute("SELECT * FROM task WHERE id = ? AND user_id = ?", (task_id, current_user.id)).fetchone()
    if not task:
        flash("Task not found or unauthorized.", "warning")
        return redirect(url_for('todo'))
    new_content = request.form.get('content')
    if new_content and new_content.strip() != task['content']:
        db.execute("UPDATE task SET content = ? WHERE id = ?", (new_content.strip(), task_id))
        db.commit()
        if not send_email("Task Edited", f"Task updated to: {new_content}"):
            flash("Email notification failed. Check server logs.", "warning")
        else:
            flash("Task edited successfully!", "success")
    return redirect(url_for('todo'))

if __name__ == '__main__':
    with app.app_context():
        db = get_db()
        # Drop existing tables (optional, only if you can lose data)
        db.execute("DROP TABLE IF EXISTS user")
        db.execute("DROP TABLE IF EXISTS task")
        # Create tables with updated schema
        db.execute('''CREATE TABLE user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT
        )''')
        db.execute('''CREATE TABLE task (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            completed BOOLEAN DEFAULT 0,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES user(id)
        )''')
        db.commit()
    app.run(debug=True)