#User = admin
#pass = password

print("Script is starting...")

from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re
import time
from urllib.parse import unquote


print("Imports successful")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'alyanany'  # It's better to use a more complex secret key in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///waf.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

print("Flask app and SQLAlchemy initialized")

# Model definitions
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class WAFConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sql_injection_pattern = db.Column(db.String(500), nullable=False)
    xss_pattern = db.Column(db.String(500), nullable=False)
    path_traversal_pattern = db.Column(db.String(500), nullable=False)
    rate_limit = db.Column(db.Integer, nullable=False)
    rate_limit_period = db.Column(db.Integer, nullable=False)

class WAFLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    attack_type = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    details = db.Column(db.String(500), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def get_waf_config():
    return WAFConfig.query.first()

def check_sql_injection(input_string):
    config = get_waf_config()
    return bool(re.search(config.sql_injection_pattern, input_string, re.IGNORECASE))

def check_xss(input_string):
    config = get_waf_config()
    return bool(re.search(config.xss_pattern, input_string, re.IGNORECASE))

def check_path_traversal(input_string):
    config = get_waf_config()
    return bool(re.search(config.path_traversal_pattern, input_string))

def check_command_injection(input_string):
    pattern = r'(;|\||`|\$\(|\${).*'
    return bool(re.search(pattern, input_string))

def check_lfi(input_string):
    pattern = r'(\.\.\/|\.\.\\|\/etc\/|\/bin\/|\/home\/)'
    return bool(re.search(pattern, unquote(input_string)))

def check_rfi(input_string):
    pattern = r'(https?:\/\/|ftp:\/\/|php:\/\/|data:)'
    return bool(re.search(pattern, unquote(input_string)))

request_history = {}

def check_rate_limit(ip):
    config = get_waf_config()
    now = time.time()
    if ip not in request_history:
        request_history[ip] = []
    request_history[ip] = [t for t in request_history[ip] if now - t < config.rate_limit_period]
    request_history[ip].append(now)
    return len(request_history[ip]) > config.rate_limit

def log_attack(attack_type, ip_address, details):
    log = WAFLog(attack_type=attack_type, ip_address=ip_address, details=details)
    db.session.add(log)
    db.session.commit()

# WAF middleware
@app.before_request
def waf():
    if request.path.startswith('/dashboard') or request.path == '/login':
        return  # Skip WAF for dashboard routes and login

    if check_rate_limit(request.remote_addr):
        log_attack("Rate Limit Exceeded", request.remote_addr, "Too many requests")
        return jsonify(error="Too many requests"), 429

    if check_path_traversal(request.path) or check_lfi(request.path):
        log_attack("Path Traversal/LFI", request.remote_addr, f"Suspicious path: {request.path}")
        return jsonify(error="Forbidden"), 403

    for param, value in request.values.items():
        if check_sql_injection(value):
            log_attack("SQL Injection", request.remote_addr, f"Suspicious parameter: {param}={value}")
            return jsonify(error="Forbidden"), 403
        if check_xss(value):
            log_attack("XSS", request.remote_addr, f"Suspicious parameter: {param}={value}")
            return jsonify(error="Forbidden"), 403
        if check_command_injection(value):
            log_attack("Command Injection", request.remote_addr, f"Suspicious parameter: {param}={value}")
            return jsonify(error="Forbidden"), 403
        if check_rfi(value):
            log_attack("Remote File Inclusion", request.remote_addr, f"Suspicious parameter: {param}={value}")
            return jsonify(error="Forbidden"), 403

# Routes
@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/dashboard/users')
@login_required
def user_list():
    users = User.query.all()
    return render_template('user_list.html', users=users)

@app.route('/dashboard/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('add_user'))
        
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('New user added successfully.')
        return redirect(url_for('user_list'))
    
    return render_template('add_user.html')

@app.route('/dashboard/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        if request.form['password']:
            user.set_password(request.form['password'])
        db.session.commit()
        flash('User updated successfully.')
        return redirect(url_for('user_list'))
    
    return render_template('edit_user.html', user=user)

@app.route('/dashboard/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account.')
        return redirect(url_for('user_list'))
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.')
    return redirect(url_for('user_list'))

@app.route('/dashboard/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        if current_user.check_password(request.form['current_password']):
            current_user.set_password(request.form['new_password'])
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect current password.')
    return render_template('change_password.html')

@app.route('/dashboard/config', methods=['GET', 'POST'])
@login_required
def config():
    if request.method == 'POST':
        config = get_waf_config()
        config.sql_injection_pattern = request.form['sql_injection_pattern']
        config.xss_pattern = request.form['xss_pattern']
        config.path_traversal_pattern = request.form['path_traversal_pattern']
        config.rate_limit = int(request.form['rate_limit'])
        config.rate_limit_period = int(request.form['rate_limit_period'])
        db.session.commit()
        return jsonify(success=True)
    config = get_waf_config()
    return jsonify(config=config.__dict__)

@app.route('/dashboard/logs')
@login_required
def logs():
    page = request.args.get('page', 1, type=int)
    logs = WAFLog.query.order_by(WAFLog.timestamp.desc()).paginate(page=page, per_page=20)
    return jsonify(logs=[log.__dict__ for log in logs.items], total=logs.total)

def create_test_user():
    if not User.query.filter_by(username='admin').first():
        user = User(username='admin')
        user.set_password('password')
        db.session.add(user)
        db.session.commit()

print("Defining routes complete")

if __name__ == '__main__':
    print("Entering main block")
    try:
        with app.app_context():
            print("Creating database tables...")
            db.create_all()
            print("Database tables created")

            create_test_user()
            if not WAFConfig.query.first():
                print("Initializing WAF configuration...")
                initial_config = WAFConfig(
                    sql_injection_pattern=r"(\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|DROP|UNION|TABLE|OR|AND)\b|\d=\d|\w=\w)",
                    xss_pattern=r"<[^>]*script|javascript:|on\w+\s*=|data:text/html",
                    path_traversal_pattern=r"\.\.\/|\.\.\\",
                    rate_limit=10,
                    rate_limit_period=60
                )
                db.session.add(initial_config)
                db.session.commit()
                print("WAF configuration initialized")
        print("Starting Flask development server...")
        app.run(debug=True)
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        print(traceback.format_exc())
    print("Application execution complete")