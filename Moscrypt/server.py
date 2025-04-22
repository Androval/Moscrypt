from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session, jsonify, send_file
from models import db, Key, User, KeySession, SessionParticipant, encrypt_key, decrypt_key, create_session_key, encrypt_session_key, cipher, SessionMessage, SessionFile, encrypt_message, decrypt_message, encrypt_file, decrypt_file
from config import Config
import logging
import bcrypt
from cryptography.fernet import Fernet
import re
import os
import datetime
from werkzeug.utils import secure_filename
from functools import wraps
from utils import sanitize_html, sanitize_filename, xss_protect
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config.from_object(Config)

# Configure Jinja2 to auto-escape all variables
app.jinja_env.autoescape = True

# Add custom Jinja2 filters
@app.template_filter('now')
def _jinja2_filter_now(format_string='%Y'):
    """Return the current time formatted according to the format string."""
    return datetime.datetime.now().strftime(format_string)

# Configure app to handle proxies correctly (for HTTPS detection)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Configure session security
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=1)  # 1 hour session lifetime
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Force HTTPS redirect
@app.before_request
def force_https():
    # Check if we're already using HTTPS or running in development
    if not request.is_secure and app.config.get('FORCE_HTTPS', False) and request.endpoint != 'static':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

# Set up login security parameters
LOGIN_ATTEMPTS_ALLOWED = 5  # Maximum number of failed login attempts
LOCKOUT_TIME = 15  # Lockout time in minutes

db.init_app(app)

# Directory to store uploaded files
USER_VAULT = 'vault'
ADMIN_VAULT = 'admin_vault'
app.config['USER_VAULT'] = USER_VAULT
app.config['ADMIN_VAULT'] = ADMIN_VAULT

# Ensure the vault directories exist
os.makedirs(USER_VAULT, exist_ok=True)
os.makedirs(ADMIN_VAULT, exist_ok=True)

# Set up logging
logging.basicConfig(level=logging.INFO)

# Add security headers to all responses
@app.after_request
def add_security_headers(response):
    # Content Security Policy
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'"
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Clickjacking protection
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Enable HSTS when HTTPS is enabled
    if app.config.get('FORCE_HTTPS', False):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
            
            user = User.query.get(session['user_id'])
            if not user or user.role not in allowed_roles:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/login', methods=['GET', 'POST'])
@xss_protect
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Get user by username
        user = User.query.filter_by(username=username).first()
        
        # Check if user exists
        if not user:
            # Use same error message to avoid username enumeration
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
            
        # Check if account is locked due to too many failed attempts
        if user.failed_login_attempts >= LOGIN_ATTEMPTS_ALLOWED:
            # Check if lockout period has expired
            if user.last_failed_login:
                lockout_expiry = user.last_failed_login + datetime.timedelta(minutes=LOCKOUT_TIME)
                if datetime.datetime.utcnow() < lockout_expiry:
                    remaining_minutes = int((lockout_expiry - datetime.datetime.utcnow()).total_seconds() / 60)
                    flash(f'Account temporarily locked due to too many failed attempts. Try again in {remaining_minutes} minutes.', 'error')
                    # Log the failed login attempt for security auditing
                    logging.warning(f"Login attempted on locked account: {username}")
                    return redirect(url_for('login'))
                else:
                    # Lockout period expired, reset the counter
                    user.failed_login_attempts = 0
                    
        # Check if user is KEK revoked
        if user.is_kek_revoked:
            flash('Your account has been locked. Please contact an administrator.', 'error')
            return redirect(url_for('login'))
        
        # Check password
        if bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            # Reset failed login attempts on successful login
            user.failed_login_attempts = 0
            user.last_login = datetime.datetime.utcnow()
            db.session.commit()
            
            # Set session to be permanent with the lifetime defined above
            session.permanent = True
            
            # Store user ID, role, and a unique session identifier
            session['user_id'] = user.id
            session['role'] = user.role
            session['_id'] = os.urandom(16).hex()  # Session identifier to prevent session fixation
            
            flash('Successfully logged in!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('vault'))
        else:
            # Increment failed login attempts
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.datetime.utcnow()
            db.session.commit()
            
            # Log the failed login attempt
            logging.warning(f"Failed login attempt for user: {username}")
            
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/admin_dashboard')
@role_required(['admin'])
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin_vault', methods=['GET', 'POST'])
@role_required(['admin'])
@xss_protect
def admin_vault():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file:
            filename = secure_filename(sanitize_filename(file.filename))
            file.save(os.path.join(app.config['ADMIN_VAULT'], filename))
            flash('File successfully uploaded to admin vault', 'success')
            return redirect(url_for('admin_vault'))
    
    admin_files = os.listdir(app.config['ADMIN_VAULT'])
    user_files = os.listdir(app.config['USER_VAULT'])
    return render_template('admin_vault.html', admin_files=admin_files, user_files=user_files)

@app.route('/admin_vault/<filename>')
@role_required(['admin'])
def admin_file(filename):
    return send_from_directory(app.config['ADMIN_VAULT'], filename)

@app.route('/vault', methods=['GET', 'POST'])
@role_required(['user', 'admin'])
@xss_protect
def vault():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        if file:
            filename = secure_filename(sanitize_filename(file.filename))
            file.save(os.path.join(app.config['USER_VAULT'], filename))
            flash('File successfully uploaded', 'success')
            return redirect(url_for('vault'))
    
    files = os.listdir(app.config['USER_VAULT'])
    user = User.query.get(session['user_id'])
    return render_template('vault.html', files=files, is_admin=user.role == 'admin')

@app.route('/vault/<filename>')
@role_required(['user', 'admin'])
def uploaded_file(filename):
    return send_from_directory(app.config['USER_VAULT'], filename)

def validate_password(password):
    """
    Validate password strength requirements.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    
    return True, ""

def create_user(username, password):
    # Check if username already exists
    if User.query.filter_by(username=username).first():
        raise ValueError("Username already exists")

    # Validate password strength
    is_valid, error_message = validate_password(password)
    if not is_valid:
        raise ValueError(error_message)

    # Generate a unique salt for this user
    salt = bcrypt.gensalt()
    
    # Hash the password with the salt
    password_bytes = password.encode('utf-8')
    password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
    
    # Generate a KEK for the user
    user_kek = Fernet.generate_key().decode('utf-8')
    
    # Create new user with role 'user'
    new_user = User(
        username=username,
        password_hash=password_hash,
        password_salt=salt.decode('utf-8'),
        kek=user_kek,
        role='user',
        last_password_change=datetime.datetime.utcnow()
    )
    
    # Add to database
    db.session.add(new_user)
    db.session.commit()
    
    # Log the creation of a new user
    logging.info(f"New user created: {username}")
    
    return new_user

@app.route('/create_user', methods=['GET', 'POST'])
@xss_protect
def user_creation():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Both username and password are required', 'error')
            return redirect(url_for('user_creation'))
            
        try:
            user = create_user(username, password)
            flash('User created successfully!', 'success')
            return redirect(url_for('home'))
        except ValueError as e:
            flash(str(e), 'error')
            return redirect(url_for('user_creation'))
        except Exception as e:
            flash(f'Error creating user: {str(e)}', 'error')
            return redirect(url_for('user_creation'))
            
    return render_template('create_user.html')

def create_initial_admin():
    """Create the initial admin user if no admin exists."""
    try:
        # Check if any admin user exists
        admin_exists = User.query.filter_by(role='admin').first()
        if not admin_exists:
            # Create admin user with default credentials
            username = 'admin'
            password = 'Admin@123'  # This is temporary and should be changed immediately
            
            # Generate a unique salt for the admin
            salt = bcrypt.gensalt()
            
            # Hash the password with the salt
            password_bytes = password.encode('utf-8')
            password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
            
            # Generate a KEK for the admin
            admin_kek = Fernet.generate_key().decode('utf-8')
            
            # Create admin user
            admin_user = User(
                username=username,
                password_hash=password_hash,
                password_salt=salt.decode('utf-8'),
                kek=admin_kek,
                role='admin',
                last_password_change=datetime.datetime.utcnow()
            )
            
            db.session.add(admin_user)
            db.session.commit()
            
            # Use secure logging instead of printing credentials to stdout
            logging.info("Initial admin user created successfully")
            logging.warning("Default admin credentials are in use - password change required")
            
            # Print warning to console but don't show the credentials
            print("\n" + "="*50)
            print("Initial admin user created with default credentials")
            print("PLEASE CHANGE THE ADMIN PASSWORD IMMEDIATELY AFTER LOGGING IN!")
            print("="*50 + "\n")
    except Exception as e:
        logging.error(f"Error creating initial admin user: {e}")

@app.route('/logout')
def logout():
    session.clear()
    flash('Successfully logged out!', 'success')
    return redirect(url_for('login'))

# Create the database tables and initial admin
try:
    with app.app_context():
        db.create_all()
        create_initial_admin()
        logging.info("Database tables created successfully")
except Exception as e:
    logging.error(f"Error creating database tables: {e}")

@app.route('/')
@role_required(['user', 'admin'])
def home():
    keys = Key.query.filter_by(user_id=session['user_id']).all()
    return render_template('index.html', keys=keys)

@app.route('/add_key', methods=['POST'])
@role_required(['user', 'admin'])
@xss_protect
def add_key():
    key_name = request.form.get('key_name')
    key_value = request.form.get('key_value')
    if key_name and key_value:
        new_key = Key(
            key_name=key_name,
            encrypted_key=encrypt_key(key_value),
            user_id=session['user_id']
        )
        db.session.add(new_key)
        db.session.commit()
        flash('Key added successfully!', 'success')
    return redirect(url_for('vault'))

@app.route('/view_key/<int:key_id>')
@role_required(['user', 'admin'])
def view_key(key_id):
    key = Key.query.filter_by(id=key_id, user_id=session['user_id']).first()
    if key:
        decrypted_key = decrypt_key(key.encrypted_key)
        return f"Decrypted Key: {decrypted_key}"
    return "Key not found", 404

@app.route('/admin/users')
@role_required(['admin'])
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/users/create', methods=['POST'])
@role_required(['admin'])
@xss_protect
def create_admin_user():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role', 'user')
    
    try:
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('manage_users'))

        # Validate password strength
        is_valid, error_message = validate_password(password)
        if not is_valid:
            flash(error_message, 'error')
            return redirect(url_for('manage_users'))

        # Generate a unique salt
        salt = bcrypt.gensalt()
        
        # Hash the password with the salt
        password_bytes = password.encode('utf-8')
        password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
        
        # Generate a KEK for the user
        user_kek = Fernet.generate_key().decode('utf-8')
        
        # Create new user
        new_user = User(
            username=username,
            password_hash=password_hash,
            password_salt=salt.decode('utf-8'),
            kek=user_kek,
            role=role,
            last_password_change=datetime.datetime.utcnow()
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        # Log the creation of a new user
        logging.info(f"Admin created new user: {username} with role {role}")
        
        flash('User created successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating user: {str(e)}")
        flash(f'Error creating user: {str(e)}', 'error')
    
    return redirect(url_for('manage_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@role_required(['admin'])
def delete_user(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('manage_users'))
            
        if user.role == 'admin':
            admin_count = User.query.filter_by(role='admin').count()
            if admin_count <= 1:
                flash('Cannot delete the last admin user', 'error')
                return redirect(url_for('manage_users'))
        
        # Delete all keys associated with the user
        Key.query.filter_by(user_id=user_id).delete()
        
        # Delete the user
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully', 'success')
        
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')
    
    return redirect(url_for('manage_users'))

@app.route('/admin/users/<int:user_id>/keys')
@role_required(['admin'])
def user_keys(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('manage_users'))
    
    keys = Key.query.filter_by(user_id=user_id).all()
    return render_template('user_keys.html', user=user, keys=keys)

@app.route('/admin/keys/<int:key_id>/revoke', methods=['POST'])
@role_required(['admin'])
def revoke_key(key_id):
    try:
        key = Key.query.get(key_id)
        if not key:
            flash('Key not found', 'error')
        else:
            db.session.delete(key)
            db.session.commit()
            flash('Key revoked successfully', 'success')
    except Exception as e:
        flash(f'Error revoking key: {str(e)}', 'error')
    
    return redirect(url_for('user_keys', user_id=key.user_id))

@app.route('/admin/users/<int:user_id>/revoke_kek', methods=['POST'])
@role_required(['admin'])
def revoke_user_kek(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('manage_users'))
            
        if user.role == 'admin':
            admin_count = User.query.filter_by(role='admin', is_kek_revoked=False).count()
            if admin_count <= 1 and not user.is_kek_revoked:
                flash('Cannot revoke KEK of the last active admin', 'error')
                return redirect(url_for('manage_users'))
        
        user.is_kek_revoked = True
        db.session.commit()
        flash('User KEK revoked successfully. User has been locked out.', 'success')
        
    except Exception as e:
        flash(f'Error revoking KEK: {str(e)}', 'error')
    
    return redirect(url_for('manage_users'))

@app.route('/admin/users/<int:user_id>/reinstate_kek', methods=['POST'])
@role_required(['admin'])
def reinstate_user_kek(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('manage_users'))
        
        # Generate a new KEK
        new_kek = Fernet.generate_key().decode('utf-8')
        user.kek = new_kek
        user.is_kek_revoked = False
        db.session.commit()
        flash('User KEK reinstated successfully. User can now log in.', 'success')
        
    except Exception as e:
        flash(f'Error reinstating KEK: {str(e)}', 'error')
    
    return redirect(url_for('manage_users'))

@app.route('/change_password', methods=['GET', 'POST'])
@xss_protect
def change_password():
    if 'user_id' not in session:
        flash('Please log in to change your password.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Verify current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), user.password_hash.encode('utf-8')):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('change_password'))
        
        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('change_password'))
        
        # Validate new password
        is_valid, error_message = validate_password(new_password)
        if not is_valid:
            flash(error_message, 'error')
            return redirect(url_for('change_password'))
        
        # Generate a new salt and hash the password
        salt = bcrypt.gensalt()
        password_bytes = new_password.encode('utf-8')
        password_hash = bcrypt.hashpw(password_bytes, salt).decode('utf-8')
        
        user.password_hash = password_hash
        user.password_salt = salt.decode('utf-8')
        user.last_password_change = datetime.datetime.utcnow()
        db.session.commit()
        
        # Log the password change
        logging.info(f"Password changed for user: {user.username}")
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('vault') if user.role == 'user' else url_for('admin_dashboard'))
    
    return render_template('change_password.html')

@app.route('/sessions')
@role_required(['user', 'admin'])
def list_sessions():
    """List all sessions the user is part of."""
    user = User.query.get(session['user_id'])
    created_sessions = KeySession.query.filter_by(creator_id=user.id).all()
    participating = SessionParticipant.query.filter_by(user_id=user.id).all()
    return render_template('sessions.html', 
                         created_sessions=created_sessions,
                         participating=participating)

@app.route('/sessions/create', methods=['GET', 'POST'])
@role_required(['user', 'admin'])
@xss_protect
def create_session():
    """Create a new key session."""
    if request.method == 'POST':
        session_name = request.form.get('session_name')
        # Handle both single and multiple participant selections
        participant_ids = request.form.getlist('participants') if hasattr(request.form, 'getlist') else []
        if not participant_ids and 'participants' in request.form:
            # If it's a single value, convert it to a list
            participant_ids = [request.form['participants']]
        
        if not session_name:
            flash('Session name is required', 'error')
            return redirect(url_for('create_session'))
            
        try:
            # Generate session key
            session_key = create_session_key()
            
            # Create new session
            new_session = KeySession(
                name=session_name,
                session_key=cipher.encrypt(session_key),  # Encrypt with master key
                creator_id=session['user_id']
            )
            db.session.add(new_session)
            db.session.commit()  # Commit to get the session ID
            
            # Add creator as participant
            creator = User.query.get(session['user_id'])
            creator_participant = SessionParticipant(
                session_id=new_session.id,
                user_id=creator.id,
                encrypted_session_key=encrypt_session_key(session_key, creator.kek)
            )
            db.session.add(creator_participant)
            
            # Add other participants
            for user_id in participant_ids:
                user = User.query.get(int(user_id))
                if user and not user.is_kek_revoked:
                    participant = SessionParticipant(
                        session_id=new_session.id,
                        user_id=user.id,
                        encrypted_session_key=encrypt_session_key(session_key, user.kek)
                    )
                    db.session.add(participant)
            
            db.session.commit()
            flash('Key session created successfully!', 'success')
            return redirect(url_for('list_sessions'))
            
        except Exception as e:
            db.session.rollback()  # Rollback on error
            flash(f'Error creating session: {str(e)}', 'error')
            return redirect(url_for('create_session'))
    
    # Get list of potential participants (excluding current user and revoked users)
    available_users = User.query.filter(
        User.id != session['user_id'],
        User.is_kek_revoked == False
    ).all()
    
    return render_template('create_session.html', available_users=available_users)

@app.route('/sessions/<int:session_id>')
@role_required(['user', 'admin'])
def view_session(session_id):
    """View session details, messages, and files."""
    key_session = KeySession.query.get(session_id)
    if not key_session:
        flash('Session not found', 'error')
        return redirect(url_for('list_sessions'))
    
    # Check if user is creator or participant
    user_id = session['user_id']
    if not (key_session.creator_id == user_id or 
            SessionParticipant.query.filter_by(session_id=session_id, user_id=user_id).first()):
        flash('You do not have access to this session', 'error')
        return redirect(url_for('list_sessions'))
    
    # Get available users for adding to the session
    current_participant_ids = [p.user_id for p in key_session.participants]
    available_users = User.query.filter(
        User.id != session['user_id'],
        User.id.notin_(current_participant_ids),
        User.is_kek_revoked == False
    ).all()
    
    # Decrypt messages if there are any
    messages = []
    if key_session.messages:
        session_key = cipher.decrypt(key_session.session_key)
        for msg in key_session.messages:
            try:
                decrypted_content = decrypt_message(msg.encrypted_content, session_key)
                messages.append({
                    'content': decrypted_content,
                    'sender': msg.sender,
                    'created_at': msg.created_at
                })
            except Exception as e:
                flash(f'Error decrypting message: {str(e)}', 'error')
    
    return render_template('view_session.html', 
                         key_session=key_session,
                         available_users=available_users,
                         messages=messages)

@app.route('/sessions/<int:session_id>/add_participant', methods=['POST'])
@role_required(['user', 'admin'])
@xss_protect
def add_participant(session_id):
    """Add a new participant to an existing session."""
    key_session = KeySession.query.get(session_id)
    if not key_session or key_session.creator_id != session['user_id']:
        flash('Unauthorized or session not found', 'error')
        return redirect(url_for('list_sessions'))
    
    user_id = request.form.get('user_id')
    user = User.query.get(int(user_id))
    
    if not user or user.is_kek_revoked:
        flash('Invalid user or user access revoked', 'error')
        return redirect(url_for('view_session', session_id=session_id))
    
    try:
        # Decrypt session key with master key
        session_key = cipher.decrypt(key_session.session_key)
        
        # Create new participant
        participant = SessionParticipant(
            session_id=session_id,
            user_id=user.id,
            encrypted_session_key=encrypt_session_key(session_key, user.kek)
        )
        db.session.add(participant)
        db.session.commit()
        
        flash('Participant added successfully!', 'success')
    except Exception as e:
        flash(f'Error adding participant: {str(e)}', 'error')
    
    return redirect(url_for('view_session', session_id=session_id))

@app.route('/sessions/<int:session_id>/remove_participant/<int:user_id>', methods=['POST'])
@role_required(['user', 'admin'])
def remove_participant(session_id, user_id):
    """Remove a participant from a session."""
    key_session = KeySession.query.get(session_id)
    if not key_session or key_session.creator_id != session['user_id']:
        flash('Unauthorized or session not found', 'error')
        return redirect(url_for('list_sessions'))
    
    try:
        participant = SessionParticipant.query.filter_by(
            session_id=session_id,
            user_id=user_id
        ).first()
        
        if participant:
            db.session.delete(participant)
            db.session.commit()
            flash('Participant removed successfully!', 'success')
        else:
            flash('Participant not found', 'error')
    except Exception as e:
        flash(f'Error removing participant: {str(e)}', 'error')
    
    return redirect(url_for('view_session', session_id=session_id))

@app.route('/sessions/<int:session_id>/close', methods=['POST'])
@role_required(['user', 'admin'])
def close_session(session_id):
    """Close a key session."""
    key_session = KeySession.query.get(session_id)
    if not key_session or key_session.creator_id != session['user_id']:
        flash('Unauthorized or session not found', 'error')
        return redirect(url_for('list_sessions'))
    
    try:
        key_session.is_active = False
        db.session.commit()
        flash('Session closed successfully!', 'success')
    except Exception as e:
        flash(f'Error closing session: {str(e)}', 'error')
    
    return redirect(url_for('list_sessions'))

@app.route('/sessions/<int:session_id>/send_message', methods=['POST'])
@role_required(['user', 'admin'])
@xss_protect
def send_message(session_id):
    """Send a message in a key session."""
    key_session = KeySession.query.get(session_id)
    if not key_session or not key_session.is_active:
        flash('Session not found or inactive', 'error')
        return redirect(url_for('list_sessions'))
    
    # Check if user is a participant
    participant = SessionParticipant.query.filter_by(
        session_id=session_id,
        user_id=session['user_id']
    ).first()
    
    if not participant:
        flash('You are not a participant in this session', 'error')
        return redirect(url_for('list_sessions'))
    
    message_content = request.form.get('message')
    if not message_content:
        flash('Message cannot be empty', 'error')
        return redirect(url_for('view_session', session_id=session_id))
    
    try:
        # Decrypt session key
        session_key = cipher.decrypt(key_session.session_key)
        
        # Create and encrypt message
        encrypted_content = encrypt_message(message_content, session_key)
        
        # Save message
        new_message = SessionMessage(
            session_id=session_id,
            sender_id=session['user_id'],
            encrypted_content=encrypted_content
        )
        db.session.add(new_message)
        db.session.commit()
        
        flash('Message sent successfully!', 'success')
    except Exception as e:
        flash(f'Error sending message: {str(e)}', 'error')
    
    return redirect(url_for('view_session', session_id=session_id))

@app.route('/sessions/<int:session_id>/share_file', methods=['POST'])
@role_required(['user', 'admin'])
@xss_protect
def share_file(session_id):
    """Share a file in a key session."""
    key_session = KeySession.query.get(session_id)
    if not key_session or not key_session.is_active:
        flash('Session not found or inactive', 'error')
        return redirect(url_for('list_sessions'))
    
    # Check if user is a participant
    participant = SessionParticipant.query.filter_by(
        session_id=session_id,
        user_id=session['user_id']
    ).first()
    
    if not participant:
        flash('You are not a participant in this session', 'error')
        return redirect(url_for('list_sessions'))
    
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('view_session', session_id=session_id))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('view_session', session_id=session_id))
    
    try:
        # Read and encrypt file data
        file_data = file.read()
        session_key = cipher.decrypt(key_session.session_key)
        encrypted_file = encrypt_file(file_data, session_key)
        
        # Save file with sanitized filename
        new_file = SessionFile(
            session_id=session_id,
            uploader_id=session['user_id'],
            filename=secure_filename(sanitize_filename(file.filename)),
            encrypted_file=encrypted_file
        )
        db.session.add(new_file)
        db.session.commit()
        
        flash('File shared successfully!', 'success')
    except Exception as e:
        flash(f'Error sharing file: {str(e)}', 'error')
    
    return redirect(url_for('view_session', session_id=session_id))

@app.route('/sessions/<int:session_id>/download_file/<int:file_id>')
@role_required(['user', 'admin'])
def download_file(session_id, file_id):
    """Download a shared file from a key session."""
    key_session = KeySession.query.get(session_id)
    session_file = SessionFile.query.get(file_id)
    
    if not key_session or not session_file or session_file.session_id != session_id:
        flash('File not found', 'error')
        return redirect(url_for('list_sessions'))
    
    # Check if user is a participant
    participant = SessionParticipant.query.filter_by(
        session_id=session_id,
        user_id=session['user_id']
    ).first()
    
    if not participant:
        flash('You are not a participant in this session', 'error')
        return redirect(url_for('list_sessions'))
    
    try:
        # Decrypt file
        session_key = cipher.decrypt(key_session.session_key)
        decrypted_file = decrypt_file(session_file.encrypted_file, session_key)
        
        # Create response
        from io import BytesIO
        return send_file(
            BytesIO(decrypted_file),
            download_name=session_file.filename,
            as_attachment=True
        )
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('view_session', session_id=session_id))

if __name__ == '__main__':
    app.run(debug=False)