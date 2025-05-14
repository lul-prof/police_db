from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from config import config




app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crime_database.db'
app.config['UPLOAD_FOLDER'] = 'static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config.from_object(config['development'])  # or 'production' for production environment

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'police', 'user'

class Criminal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_names = db.Column(db.String(200), nullable=False)
    nationality = db.Column(db.String(100), nullable=False)
    county = db.Column(db.String(100), nullable=False)
    national_id = db.Column(db.String(20), unique=True, nullable=False)
    age = db.Column(db.Integer, nullable=False)
    sex = db.Column(db.String(10), nullable=False)
    crimes_committed = db.Column(db.Text, nullable=False)
    contact = db.Column(db.String(100))
    mugshot = db.Column(db.String(200))
    arrest_date = db.Column(db.DateTime, nullable=False)
    arresting_officer = db.Column(db.String(200), nullable=False)
    prison = db.Column(db.String(200), nullable=False)
    expected_release_date = db.Column(db.DateTime, nullable=False)

class CrimeReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='pending')
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = 'user'  # Default role

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful')
        return redirect(url_for('login'))
    return render_template('auth/register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/search', methods=['GET'])
@login_required
def search_criminal():
    query = request.args.get('query', '')
    if query:
        criminals = Criminal.query.filter(
            (Criminal.full_names.ilike(f'%{query}%')) |
            (Criminal.county.ilike(f'%{query}%'))
        ).all()
    else:
        criminals = []
    return render_template('public/search.html', criminals=criminals)

@app.route('/report-crime', methods=['GET', 'POST'])
@login_required
def report_crime():
    if request.method == 'POST':
        description = request.form.get('description')
        location = request.form.get('location')
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')

        crime_report = CrimeReport(
            description=description,
            location=location,
            latitude=latitude,
            longitude=longitude,
            reported_by=current_user.id
        )
        db.session.add(crime_report)
        db.session.commit()
        flash('Crime reported successfully')
        return redirect(url_for('home'))
    return render_template('public/report_crime.html')

@app.route('/police/add-criminal', methods=['GET', 'POST'])
@login_required
def add_criminal():
    if current_user.role != 'police' and current_user.role != 'admin':
        flash('Unauthorized access')
        return redirect(url_for('home'))

    if request.method == 'POST':
        mugshot = request.files['mugshot']
        filename = None
        if mugshot and allowed_file(mugshot.filename):
            filename = secure_filename(mugshot.filename)
            mugshot.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        new_criminal = Criminal(
            full_names=request.form.get('full_names'),
            nationality=request.form.get('nationality'),
            county=request.form.get('county'),
            national_id=request.form.get('national_id'),
            age=int(request.form.get('age')),
            sex=request.form.get('sex'),
            crimes_committed=request.form.get('crimes_committed'),
            contact=request.form.get('contact'),
            mugshot=filename,
            arrest_date=datetime.strptime(request.form.get('arrest_date'), '%Y-%m-%d'),
            arresting_officer=request.form.get('arresting_officer'),
            prison=request.form.get('prison'),
            expected_release_date=datetime.strptime(request.form.get('expected_release_date'), '%Y-%m-%d')
        )
        db.session.add(new_criminal)
        db.session.commit()
        flash('Criminal record added successfully')
        return redirect(url_for('admin_dashboard'))
    return render_template('police/add_criminal.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Unauthorized access')
        return redirect(url_for('home'))
    
    criminals = Criminal.query.all()
    crime_reports = CrimeReport.query.all()
    return render_template('admin/dashboard.html', criminals=criminals, crime_reports=crime_reports)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
