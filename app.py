from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from mysql.connector import Error
import datetime
import os
from werkzeug.utils import secure_filename
from functools import wraps
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import atexit

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Configure upload folder
UPLOAD_FOLDER = 'static/uploads/resumes'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB limit

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db_config = {
    "host": "jobswift.cnpcskbagtmj.us-east-1.rds.amazonaws.com",
    "user": "admin",
    "password": "Admin123",
    "database": "jobswift"
}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] != role:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def create_tables():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            age INT NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            role ENUM('jobseeker', 'recruiter') NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS jobseeker_profiles (
            user_id INT PRIMARY KEY,
            education TEXT,
            experience TEXT,
            skills TEXT,
            portfolio_links TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS job_preferences (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            position VARCHAR(100) NOT NULL,
            location VARCHAR(100) NOT NULL,
            experience VARCHAR(50) NOT NULL,
            resume_link VARCHAR(255),
            auto_apply BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS recruiter_profiles (
            user_id INT PRIMARY KEY,
            company_name VARCHAR(100) NOT NULL,
            company_details TEXT,
            workplace_photos TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS job_posts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            recruiter_id INT NOT NULL,
            position VARCHAR(100) NOT NULL,
            description TEXT NOT NULL,
            location VARCHAR(100) NOT NULL,
            experience VARCHAR(50) NOT NULL,
            posted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expiry_date DATE NOT NULL,
            status ENUM('active', 'expired') DEFAULT 'active',
            FOREIGN KEY (recruiter_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS job_applications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            applicant_id INT NOT NULL,
            job_id INT NOT NULL,
            resume_link VARCHAR(255) NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status ENUM('pending', 'accepted', 'rejected', 'expired') DEFAULT 'pending',
            FOREIGN KEY (applicant_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (job_id) REFERENCES job_posts(id) ON DELETE CASCADE
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS jobseeker_notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            application_id INT NOT NULL,
            message TEXT NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (application_id) REFERENCES job_applications(id) ON DELETE CASCADE
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS recruiter_notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            application_id INT NOT NULL,
            message TEXT NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (application_id) REFERENCES job_applications(id) ON DELETE CASCADE
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS jobseeker_analytics (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            profile_views INT DEFAULT 0,
            applications_submitted INT DEFAULT 0,
            applications_accepted INT DEFAULT 0,
            applications_rejected INT DEFAULT 0,
            auto_apply_success_rate FLOAT DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS recruiter_analytics (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            jobs_posted INT DEFAULT 0,
            total_applications INT DEFAULT 0,
            applications_accepted INT DEFAULT 0,
            applications_rejected INT DEFAULT 0,
            acceptance_rate FLOAT DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS auto_apply_log (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            job_id INT NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success_status BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (job_id) REFERENCES job_posts(id) ON DELETE CASCADE
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS job_filters (
            id INT AUTO_INCREMENT PRIMARY KEY,
            filter_type VARCHAR(50) NOT NULL,
            filter_value VARCHAR(100) NOT NULL
        )
        """)
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(100) NOT NULL,
            token VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
        )
        """)
        
        conn.commit()
        print("Tables created successfully")
        
    except Error as e:
        print(f"Error creating tables: {e}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

create_tables()

def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

# Auto-Apply Job Function
def auto_apply_jobs():
    try:
        conn = get_db_connection()
        if not conn:
            return
            
        cursor = conn.cursor(dictionary=True)
        
        # Get all active auto-apply preferences with resume links
        cursor.execute("""
            SELECT * FROM job_preferences 
            WHERE auto_apply = TRUE
            AND resume_link IS NOT NULL
        """)
        preferences = cursor.fetchall()
        
        for pref in preferences:
            # Check daily limit (default to 5 if not set)
            daily_limit = pref.get('daily_limit', 5)
            cursor.execute("""
                SELECT COUNT(*) as today_count 
                FROM auto_apply_log 
                WHERE user_id = %s 
                AND DATE(applied_at) = CURDATE()
            """, (pref['user_id'],))
            today_count = cursor.fetchone()['today_count']
            
            if today_count >= daily_limit:
                continue
            
            # Find matching jobs not already applied to
            cursor.execute("""
                SELECT jp.* FROM job_posts jp
                WHERE jp.position LIKE %s
                AND jp.location LIKE %s
                AND jp.experience = %s
                AND jp.status = 'active'
                AND jp.expiry_date >= CURDATE()
                AND NOT EXISTS (
                    SELECT 1 FROM job_applications ja
                    WHERE ja.job_id = jp.id
                    AND ja.applicant_id = %s
                )
                AND NOT EXISTS (
                    SELECT 1 FROM auto_apply_log aal
                    WHERE aal.job_id = jp.id
                    AND aal.user_id = %s
                )
                LIMIT 1
            """, (
                f"%{pref['position']}%",
                f"%{pref['location']}%",
                pref['experience'],
                pref['user_id'],
                pref['user_id']
            ))
            matching_job = cursor.fetchone()
            
            if matching_job:
                try:
                    # Apply to the job
                    cursor.execute("""
                        INSERT INTO job_applications 
                        (applicant_id, job_id, resume_link, status)
                        VALUES (%s, %s, %s, 'pending')
                    """, (pref['user_id'], matching_job['id'], pref['resume_link']))
                    
                    application_id = cursor.lastrowid
                    
                    # Create notification for recruiter
                    cursor.execute("""
                        INSERT INTO recruiter_notifications 
                        (user_id, application_id, message)
                        SELECT recruiter_id, %s, CONCAT('New application for job: ', position)
                        FROM job_posts WHERE id = %s
                    """, (application_id, matching_job['id']))
                    
                    # Log the auto-application
                    cursor.execute("""
                        INSERT INTO auto_apply_log 
                        (user_id, job_id, success_status)
                        VALUES (%s, %s, TRUE)
                    """, (pref['user_id'], matching_job['id']))
                    
                    # Update analytics
                    cursor.execute("""
                        UPDATE jobseeker_analytics 
                        SET applications_submitted = applications_submitted + 1
                        WHERE user_id = %s
                    """, (pref['user_id'],))
                    
                    conn.commit()
                    
                    # Create notification for jobseeker
                    cursor.execute("""
                        INSERT INTO jobseeker_notifications 
                        (user_id, application_id, message)
                        VALUES (%s, %s, %s)
                    """, (pref['user_id'], application_id, 
                         f"Auto-applied to {matching_job['position']} at {matching_job['location']}"))
                    
                    conn.commit()
                    
                except Error as e:
                    conn.rollback()
                    # Log failed attempt
                    cursor.execute("""
                        INSERT INTO auto_apply_log 
                        (user_id, job_id, success_status)
                        VALUES (%s, %s, FALSE)
                    """, (pref['user_id'], matching_job['id']))
                    conn.commit()
                
    except Error as e:
        print(f"Auto-apply error: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(
    auto_apply_jobs,
    trigger=IntervalTrigger(minutes=30),
    id='auto_apply_job',
    replace_existing=True
)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

@app.context_processor
def inject_datetime():
    return {'datetime': datetime}


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        age = request.form.get('age', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        role = request.form.get('role', '').strip()
        
        if not all([name, age, email, password, confirm_password, role]):
            flash('All fields are required!', 'error')
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))
        
        try:
            conn = get_db_connection()
            if not conn:
                flash('Database connection error. Please try again later.', 'error')
                return redirect(url_for('signup'))
                
            cursor = conn.cursor()
            
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash('Email already registered! Please use a different email.', 'error')
                return redirect(url_for('signup'))
            
            cursor.execute(
                "INSERT INTO users (name, age, email, password, role) VALUES (%s, %s, %s, %s, %s)",
                (name, age, email, password, role)
            )
            user_id = cursor.lastrowid
            
            if role == 'jobseeker':
                cursor.execute(
                    "INSERT INTO jobseeker_analytics (user_id) VALUES (%s)",
                    (user_id,)
                )
            else:
                cursor.execute(
                    "INSERT INTO recruiter_analytics (user_id) VALUES (%s)",
                    (user_id,)
                )
            
            conn.commit()
            flash('Registration successful! Please login with your credentials.', 'success')
            return redirect(url_for('login'))
            
        except Error as e:
            conn.rollback()
            flash(f'Registration failed: {str(e)}', 'error')
            return redirect(url_for('signup'))
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        
        if not email or not password:
            flash('Email and password are required!', 'error')
            return redirect(url_for('login'))
        
        try:
            conn = get_db_connection()
            if not conn:
                flash('Database connection error. Please try again later.', 'error')
                return redirect(url_for('login'))
                
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            if user and user['password'] == password:
                session['user_id'] = user['id']
                session['name'] = user['name']
                session['email'] = user['email']
                session['role'] = user['role']
                
                if user['role'] == 'jobseeker':
                    cursor.execute("SELECT * FROM jobseeker_profiles WHERE user_id = %s", (user['id'],))
                    profile = cursor.fetchone()
                    if not profile:
                        flash('Please complete your profile to continue.', 'info')
                        return redirect(url_for('jobseeker_profile'))
                else:
                    cursor.execute("SELECT * FROM recruiter_profiles WHERE user_id = %s", (user['id'],))
                    profile = cursor.fetchone()
                    if not profile:
                        flash('Please complete your company profile to continue.', 'info')
                        return redirect(url_for('recruiter_profile'))
                
                flash(f'Welcome back, {user["name"]}!', 'success')
                if user['role'] == 'jobseeker':
                    return redirect(url_for('jobseeker_dashboard'))
                else:
                    return redirect(url_for('recruiter_dashboard'))
            else:
                flash('Invalid email or password! Please try again.', 'error')
                return redirect(url_for('login'))
            
        except Error as e:
            flash(f'Login error: {str(e)}', 'error')
            return redirect(url_for('login'))
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()
    
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not email:
            flash('Email is required!', 'error')
            return redirect(url_for('forgot_password'))
        
        try:
            conn = get_db_connection()
            if not conn:
                flash('Database connection error. Please try again later.', 'error')
                return redirect(url_for('forgot_password'))
                
            cursor = conn.cursor()
            
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if not cursor.fetchone():
                flash('If an account exists with this email, a password reset link has been sent.', 'info')
                return redirect(url_for('login'))
            
            flash('A password reset link has been sent to your email (simulated).', 'info')
            return redirect(url_for('login'))
            
        except Error as e:
            flash(f'Error processing request: {str(e)}', 'error')
            return redirect(url_for('forgot_password'))
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()
    
    return render_template('forgot_password.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([current_password, new_password, confirm_password]):
            flash('All fields are required!', 'error')
            return redirect(url_for('change_password'))
            
        if new_password != confirm_password:
            flash('New passwords do not match!', 'error')
            return redirect(url_for('change_password'))
            
        try:
            conn = get_db_connection()
            if not conn:
                flash('Database connection error. Please try again later.', 'error')
                return redirect(url_for('change_password'))
                
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("SELECT password FROM users WHERE id = %s", (session['user_id'],))
            user = cursor.fetchone()
            
            if user and user['password'] == current_password:
                cursor.execute("UPDATE users SET password = %s WHERE id = %s", 
                             (new_password, session['user_id']))
                conn.commit()
                flash('Password changed successfully!', 'success')
                if session['role'] == 'jobseeker':
                    return redirect(url_for('jobseeker_profile'))
                else:
                    return redirect(url_for('recruiter_profile'))
            else:
                flash('Current password is incorrect!', 'error')
                return redirect(url_for('change_password'))
                
        except Error as e:
            conn.rollback()
            flash(f'Error changing password: {str(e)}', 'error')
            return redirect(url_for('change_password'))
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()
    
    return render_template('change_password.html')

@app.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('index'))
            
        cursor = conn.cursor()
        
        # Delete user and all related data (cascading deletes should handle related tables)
        cursor.execute("DELETE FROM users WHERE id = %s", (session['user_id'],))
        
        conn.commit()
        session.clear()
        flash('Your account has been deleted successfully.', 'success')
        return redirect(url_for('index'))
        
    except Error as e:
        conn.rollback()
        flash(f'Error deleting account: {str(e)}', 'error')
        return redirect(url_for('jobseeker_profile' if session.get('role') == 'jobseeker' else 'recruiter_profile'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/logout')
def logout():
    if 'name' in session:
        flash(f'Goodbye, {session["name"]}! You have been logged out.', 'info')
    else:
        flash('You have been logged out.', 'info')
    session.clear()
    return redirect(url_for('index'))

@app.route('/jobseeker/dashboard')
@login_required
@role_required('jobseeker')
def jobseeker_dashboard():
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('index'))
            
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT * FROM jobseeker_analytics 
            WHERE user_id = %s
        """, (session['user_id'],))
        analytics = cursor.fetchone()
        
        cursor.execute("""
            SELECT ja.*, jp.position, rp.company_name, jp.expiry_date
            FROM job_applications ja
            JOIN job_posts jp ON ja.job_id = jp.id
            JOIN recruiter_profiles rp ON jp.recruiter_id = rp.user_id
            WHERE ja.applicant_id = %s
            ORDER BY ja.applied_at DESC
            LIMIT 5
        """, (session['user_id'],))
        applications = cursor.fetchall()
        
    except Error as e:
        flash(f'Error fetching dashboard data: {str(e)}', 'error')
        return redirect(url_for('jobseeker_dashboard'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return render_template('jobseeker_dashboard.html', 
                         analytics=analytics, 
                         applications=applications)


@app.route('/jobseeker/profile', methods=['GET', 'POST'])
@login_required
@role_required('jobseeker')
def jobseeker_profile():
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('jobseeker_dashboard'))
            
        cursor = conn.cursor(dictionary=True)
        
        if request.method == 'POST':
            # Handle profile updates
            education = request.form.get('education', '').strip()
            experience = request.form.get('experience', '').strip()
            skills = request.form.get('skills', '').strip()
            portfolio_links = request.form.get('portfolio_links', '').strip()
            
            cursor.execute("SELECT * FROM jobseeker_profiles WHERE user_id = %s", (session['user_id'],))
            profile = cursor.fetchone()
            
            if profile:
                cursor.execute("""
                    UPDATE jobseeker_profiles 
                    SET education = %s, experience = %s, skills = %s, portfolio_links = %s
                    WHERE user_id = %s
                """, (education, experience, skills, portfolio_links, session['user_id']))
                flash('Profile updated successfully!', 'success')
            else:
                cursor.execute("""
                    INSERT INTO jobseeker_profiles 
                    (user_id, education, experience, skills, portfolio_links)
                    VALUES (%s, %s, %s, %s, %s)
                """, (session['user_id'], education, experience, skills, portfolio_links))
                flash('Profile created successfully!', 'success')
            
            conn.commit()
            return redirect(url_for('jobseeker_profile'))
        
        # Get user data
        cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()
        
        # Get profile data
        cursor.execute("SELECT * FROM jobseeker_profiles WHERE user_id = %s", (session['user_id'],))
        profile = cursor.fetchone()
        
        # Get resume data - modified to return a single dictionary
        cursor.execute("""
            SELECT resume_link FROM job_preferences 
            WHERE user_id = %s LIMIT 1
        """, (session['user_id'],))
        resume_data = cursor.fetchone()
        
        # Create preferences dictionary with just the resume data
        preferences = {'resume_link': resume_data['resume_link']} if resume_data and resume_data.get('resume_link') else None
        
    except Error as e:
        flash(f'Error processing profile: {str(e)}', 'error')
        return redirect(url_for('jobseeker_profile'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return render_template('jobseeker_profile.html', 
                         user=user, 
                         profile=profile, 
                         preferences=preferences,
                         role='jobseeker')

@app.route('/upload-resume', methods=['POST'])
@login_required
@role_required('jobseeker')
def upload_resume():
    if 'resume' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('jobseeker_profile'))

    file = request.files['resume']
    
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('jobseeker_profile'))

    if file and allowed_file(file.filename):
        try:
            # Secure filename and save
            filename = secure_filename(f"{session['user_id']}_{file.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Store relative path in database
            resume_link = os.path.join('uploads', 'resumes', filename)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Check if user has existing preferences
            cursor.execute("SELECT id FROM job_preferences WHERE user_id = %s", (session['user_id'],))
            if not cursor.fetchone():
                # Create new preference with resume
                cursor.execute("""
                    INSERT INTO job_preferences 
                    (user_id, position, location, experience, resume_link)
                    VALUES (%s, '', '', '', %s)
                """, (session['user_id'], resume_link))
            else:
                # Update existing resume
                cursor.execute("""
                    UPDATE job_preferences 
                    SET resume_link = %s
                    WHERE user_id = %s
                """, (resume_link, session['user_id']))
            
            conn.commit()
            flash('Resume uploaded successfully!', 'success')
        except Error as e:
            conn.rollback()
            flash(f'Error updating resume: {str(e)}', 'error')
        except Exception as e:
            flash(f'Error saving file: {str(e)}', 'error')
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()
    else:
        flash('Allowed file types are PDF, DOC, and DOCX', 'error')
    
    return redirect(url_for('jobseeker_profile'))

@app.route('/delete-resume', methods=['POST'])
@login_required
@role_required('jobseeker')
def delete_resume():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get current resume path
        cursor.execute("""
            SELECT resume_link FROM job_preferences 
            WHERE user_id = %s
        """, (session['user_id'],))
        result = cursor.fetchone()
        
        if result and result.get('resume_link'):
            # Delete physical file
            file_path = os.path.join(app.static_folder, result['resume_link'])
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception as e:
                    flash(f'Error deleting file: {str(e)}', 'error')
                    return redirect(url_for('jobseeker_profile'))
            
            # Update database
            cursor.execute("""
                UPDATE job_preferences 
                SET resume_link = NULL
                WHERE user_id = %s
            """, (session['user_id'],))
            
            conn.commit()
            flash('Resume deleted successfully!', 'success')
        else:
            flash('No resume found to delete', 'warning')
            
    except Error as e:
        if conn:
            conn.rollback()
        flash(f'Database error: {str(e)}', 'error')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()
    
    return redirect(url_for('jobseeker_profile'))

@app.route('/jobseeker/job-preferences', methods=['GET', 'POST'])
@login_required
@role_required('jobseeker')
def job_preferences():
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('jobseeker_dashboard'))
            
        cursor = conn.cursor(dictionary=True)
        
        if request.method == 'POST':
            if 'delete_id' in request.form:
                pref_id = request.form['delete_id']
                cursor.execute("DELETE FROM job_preferences WHERE id = %s AND user_id = %s", 
                             (pref_id, session['user_id']))
                conn.commit()
                flash('Preference deleted successfully!', 'success')
                return redirect(url_for('job_preferences'))
            
            position = request.form.get('position', '').strip()
            location = request.form.get('location', '').strip()
            experience = request.form.get('experience', '').strip()
            resume_link = request.form.get('resume_link', '').strip()
            auto_apply = True if request.form.get('auto_apply') == 'on' else False
            daily_limit = int(request.form.get('daily_limit', 5))
            
            if not all([position, location, experience]):
                flash('Position, location, and experience are required!', 'error')
                return redirect(url_for('job_preferences'))
            
            cursor.execute("SELECT COUNT(*) as count FROM job_preferences WHERE user_id = %s", (session['user_id'],))
            count = cursor.fetchone()['count']
            
            if count >= 5 and 'pref_id' not in request.form:
                flash('You can have a maximum of 5 job preferences!', 'error')
                return redirect(url_for('job_preferences'))
            
            if 'pref_id' in request.form:
                pref_id = request.form['pref_id']
                cursor.execute("""
                    UPDATE job_preferences 
                    SET position = %s, location = %s, experience = %s, 
                        resume_link = %s, auto_apply = %s, daily_limit = %s
                    WHERE id = %s AND user_id = %s
                """, (position, location, experience, resume_link, auto_apply, daily_limit, pref_id, session['user_id']))
                flash('Preference updated successfully!', 'success')
            else:
                cursor.execute("""
                    INSERT INTO job_preferences 
                    (user_id, position, location, experience, resume_link, auto_apply, daily_limit)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (session['user_id'], position, location, experience, resume_link, auto_apply, daily_limit))
                flash('Job preference added successfully!', 'success')
            
            conn.commit()
            return redirect(url_for('job_preferences'))
        
        cursor.execute("SELECT * FROM job_preferences WHERE user_id = %s", (session['user_id'],))
        preferences = cursor.fetchall()
        
        # Check if any preference has auto-apply enabled
        any_pref_active = any(pref['auto_apply'] for pref in preferences)
        
    except Error as e:
        flash(f'Error processing job preferences: {str(e)}', 'error')
        return redirect(url_for('job_preferences'))
    except ValueError:
        flash('Daily limit must be a valid number!', 'error')
        return redirect(url_for('job_preferences'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return render_template('job_preference.html', 
                         preferences=preferences,
                         any_pref_active=any_pref_active,
                         unread_notifications=inject_unread_notifications().get('unread_notifications', 0))

@app.route('/jobseeker/jobs')
@login_required
@role_required('jobseeker')
def job_listings():
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('jobseeker_dashboard'))
            
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT jp.*, rp.company_name 
            FROM job_posts jp
            JOIN recruiter_profiles rp ON jp.recruiter_id = rp.user_id
            WHERE jp.status = 'active' AND jp.expiry_date >= CURDATE()
            ORDER BY jp.posted_at DESC
        """)
        jobs = cursor.fetchall()
        
        # Get all job IDs the user has applied to
        cursor.execute("""
            SELECT DISTINCT job_id FROM job_applications 
            WHERE applicant_id = %s
        """, (session['user_id'],))
        applied_job_ids = [row['job_id'] for row in cursor.fetchall()]
        
        cursor.execute("""
            SELECT COUNT(*) as unread_count 
            FROM jobseeker_notifications
            WHERE user_id = %s AND is_read = FALSE
        """, (session['user_id'],))
        unread_result = cursor.fetchone()
        unread_notifications = unread_result['unread_count'] if unread_result else 0
        
    except Error as e:
        flash(f'Error fetching job listings: {str(e)}', 'error')
        return redirect(url_for('jobseeker_dashboard'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    today = datetime.date.today()
    
    return render_template('job.html', 
                         jobs=jobs, 
                         applied_job_ids=applied_job_ids,
                         unread_notifications=unread_notifications,
                         today=today)


@app.context_processor
def inject_unread_notifications():
    if 'user_id' in session and session.get('role') == 'jobseeker':
        try:
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT COUNT(*) as unread_count 
                    FROM jobseeker_notifications
                    WHERE user_id = %s AND is_read = FALSE
                """, (session['user_id'],))
                result = cursor.fetchone()
                return {'unread_notifications': result['unread_count'] if result else 0}
        except Error as e:
            print(f"Error fetching unread notifications: {e}")
            return {'unread_notifications': 0}
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()
    return {'unread_notifications': 0}

@app.route('/jobseeker/apply/<int:job_id>', methods=['POST'])
@login_required
@role_required('jobseeker')
def apply_job(job_id):
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('job_listings'))
            
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id FROM job_posts 
            WHERE id = %s AND status = 'active' AND expiry_date >= CURDATE()
        """, (job_id,))
        if not cursor.fetchone():
            flash('This job is no longer available for applications.', 'error')
            return redirect(url_for('job_listings'))
        
        cursor.execute("""
            SELECT id FROM job_applications 
            WHERE applicant_id = %s AND job_id = %s
        """, (session['user_id'], job_id))
        if cursor.fetchone():
            flash('You have already applied to this job!', 'warning')
            return redirect(url_for('job_listings'))
        
        cursor.execute("""
            SELECT resume_link FROM job_preferences 
            WHERE user_id = %s LIMIT 1
        """, (session['user_id'],))
        preference = cursor.fetchone()
        resume_link = preference['resume_link'] if preference and preference['resume_link'] else ''
        
        if not resume_link:
            flash('Please set up your resume in job preferences first!', 'error')
            return redirect(url_for('job_preferences'))
        
        cursor.execute("""
            INSERT INTO job_applications 
            (applicant_id, job_id, resume_link, status)
            VALUES (%s, %s, %s, 'pending')
        """, (session['user_id'], job_id, resume_link))
        
        application_id = cursor.lastrowid
        cursor.execute("""
            INSERT INTO recruiter_notifications 
            (user_id, application_id, message)
            SELECT recruiter_id, %s, CONCAT('New application for job: ', position)
            FROM job_posts WHERE id = %s
        """, (application_id, job_id))
        
        cursor.execute("""
            UPDATE jobseeker_analytics 
            SET applications_submitted = applications_submitted + 1
            WHERE user_id = %s
        """, (session['user_id'],))
        
        conn.commit()
        flash('Application submitted successfully!', 'success')
        
    except Error as e:
        conn.rollback()
        flash(f'Error applying to job: {str(e)}', 'error')
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return redirect(url_for('job_listings'))

@app.route('/jobseeker/my-applications')
@login_required
@role_required('jobseeker')
def my_applications():
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('jobseeker_dashboard'))
            
        cursor = conn.cursor(dictionary=True)
        
        # Get applications
        cursor.execute("""
            SELECT ja.*, jp.position, jp.description, jp.location, 
                   jp.experience, rp.company_name,
                   CASE 
                       WHEN jp.expiry_date < CURDATE() THEN 'expired'
                       ELSE ja.status
                   END as display_status
            FROM job_applications ja
            JOIN job_posts jp ON ja.job_id = jp.id
            JOIN recruiter_profiles rp ON jp.recruiter_id = rp.user_id
            WHERE ja.applicant_id = %s
            ORDER BY ja.applied_at DESC
        """, (session['user_id'],))
        applications = cursor.fetchall()
        
        # Get unread notifications count
        cursor.execute("""
            SELECT COUNT(*) as unread_count 
            FROM jobseeker_notifications
            WHERE user_id = %s AND is_read = FALSE
        """, (session['user_id'],))
        unread_result = cursor.fetchone()
        unread_notifications = unread_result['unread_count'] if unread_result else 0
        
    except Error as e:
        flash(f'Error fetching applications: {str(e)}', 'error')
        return redirect(url_for('jobseeker_dashboard'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return render_template('my_applications.html', 
                         applications=applications,
                         unread_notifications=unread_notifications,
                         role='jobseeker')


@app.route('/jobseeker/notifications')
@login_required
@role_required('jobseeker')
def jobseeker_notifications():
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('jobseeker_dashboard'))
            
        cursor = conn.cursor(dictionary=True)
        
        # Get all notifications
        cursor.execute("""
            SELECT jn.*, ja.job_id, jp.position, ja.status as application_status
            FROM jobseeker_notifications jn
            JOIN job_applications ja ON jn.application_id = ja.id
            JOIN job_posts jp ON ja.job_id = jp.id
            WHERE jn.user_id = %s
            ORDER BY jn.created_at DESC
        """, (session['user_id'],))
        notifications = cursor.fetchall()
        
        # Get count of unread notifications
        cursor.execute("""
            SELECT COUNT(*) as unread_count 
            FROM jobseeker_notifications
            WHERE user_id = %s AND is_read = FALSE
        """, (session['user_id'],))
        unread_result = cursor.fetchone()
        unread_notifications = unread_result['unread_count'] if unread_result else 0
        
        # Mark all notifications as read when page is loaded
        cursor.execute("""
            UPDATE jobseeker_notifications 
            SET is_read = TRUE
            WHERE user_id = %s AND is_read = FALSE
        """, (session['user_id'],))
        conn.commit()
        
    except Error as e:
        flash(f'Error fetching notifications: {str(e)}', 'error')
        return redirect(url_for('jobseeker_dashboard'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return render_template('jobseeker_notifications.html', 
                         notifications=notifications, 
                         unread_notifications=unread_notifications,
                         role='jobseeker')

@app.route('/jobseeker/analytics')
@login_required
@role_required('jobseeker')
def jobseeker_analytics():
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('jobseeker_dashboard'))
            
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM jobseeker_analytics WHERE user_id = %s", (session['user_id'],))
        analytics = cursor.fetchone()
        
        if analytics:
            if analytics['applications_submitted'] > 0:
                analytics['success_rate'] = round(
                    (analytics['applications_accepted'] / analytics['applications_submitted']) * 100, 
                    2
                )
            else:
                analytics['success_rate'] = 0
            
            analytics['recent_views'] = analytics['profile_views']
        
    except Error as e:
        flash(f'Error fetching analytics: {str(e)}', 'error')
        return redirect(url_for('jobseeker_dashboard'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return render_template('jobseeker_analytics.html', analytics=analytics)

@app.route('/recruiter/dashboard')
@login_required
@role_required('recruiter')
def recruiter_dashboard():
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('index'))
            
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM recruiter_analytics WHERE user_id = %s", (session['user_id'],))
        analytics = cursor.fetchone()
        
        cursor.execute("""
            SELECT *, 
                   CASE 
                       WHEN expiry_date < CURDATE() THEN TRUE
                       ELSE FALSE
                   END as is_expired
            FROM job_posts 
            WHERE recruiter_id = %s
            ORDER BY posted_at DESC
            LIMIT 5
        """, (session['user_id'],))
        jobs = cursor.fetchall()
        
        cursor.execute("""
            SELECT COUNT(*) as unread_count 
            FROM recruiter_notifications
            WHERE user_id = %s AND is_read = FALSE
        """, (session['user_id'],))
        unread_notifications = cursor.fetchone()['unread_count']
        
    except Error as e:
        flash(f'Error fetching dashboard data: {str(e)}', 'error')
        return redirect(url_for('recruiter_dashboard'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return render_template('recruiter_dashboard.html', 
                         analytics=analytics, 
                         jobs=jobs,
                         unread_notifications=unread_notifications,
                         datetime=datetime)

@app.route('/recruiter/profile', methods=['GET', 'POST'])
@login_required
@role_required('recruiter')
def recruiter_profile():
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('recruiter_dashboard'))
            
        cursor = conn.cursor(dictionary=True)
        
        if request.method == 'POST':
            company_name = request.form.get('company_name', '').strip()
            company_details = request.form.get('company_details', '').strip()
            workplace_photos = request.form.get('workplace_photos', '').strip()
            
            if not company_name:
                flash('Company name is required!', 'error')
                return redirect(url_for('recruiter_profile'))
            
            cursor.execute("SELECT * FROM recruiter_profiles WHERE user_id = %s", (session['user_id'],))
            profile = cursor.fetchone()
            
            if profile:
                cursor.execute("""
                    UPDATE recruiter_profiles 
                    SET company_name = %s, company_details = %s, workplace_photos = %s
                    WHERE user_id = %s
                """, (company_name, company_details, workplace_photos, session['user_id']))
                flash('Company profile updated successfully!', 'success')
            else:
                cursor.execute("""
                    INSERT INTO recruiter_profiles 
                    (user_id, company_name, company_details, workplace_photos)
                    VALUES (%s, %s, %s, %s)
                """, (session['user_id'], company_name, company_details, workplace_photos))
                flash('Company profile created successfully!', 'success')
            
            conn.commit()
            return redirect(url_for('recruiter_profile'))
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()
        
        cursor.execute("SELECT * FROM recruiter_profiles WHERE user_id = %s", (session['user_id'],))
        profile = cursor.fetchone()
        
    except Error as e:
        flash(f'Error processing profile: {str(e)}', 'error')
        return redirect(url_for('recruiter_profile'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return render_template('recruiter_profile.html', user=user, profile=profile, role='recruiter')

@app.route('/recruiter/job-postings', methods=['GET', 'POST'])
@login_required
@role_required('recruiter')
def job_postings():
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('recruiter_dashboard'))
            
        cursor = conn.cursor(dictionary=True)
        
        if request.method == 'POST':
            if 'delete_id' in request.form:
                job_id = request.form['delete_id']
                
                cursor.execute("""
                    SELECT id FROM job_posts 
                    WHERE id = %s AND recruiter_id = %s
                """, (job_id, session['user_id']))
                if not cursor.fetchone():
                    flash('Job not found or access denied!', 'error')
                    return redirect(url_for('job_postings'))
                
                cursor.execute("DELETE FROM job_posts WHERE id = %s", (job_id,))
                conn.commit()
                flash('Job posting deleted successfully!', 'success')
                return redirect(url_for('job_postings'))
            
            if 'job_id' in request.form and 'status' in request.form:
                job_id = request.form['job_id']
                new_status = request.form['status']
                
                cursor.execute("""
                    SELECT id FROM job_posts 
                    WHERE id = %s AND recruiter_id = %s
                """, (job_id, session['user_id']))
                if not cursor.fetchone():
                    flash('Job not found or access denied!', 'error')
                    return redirect(url_for('job_postings'))
                
                cursor.execute("""
                    UPDATE job_posts 
                    SET status = %s
                    WHERE id = %s
                """, (new_status, job_id))
                conn.commit()
                
                status_msg = "reopened" if new_status == 'active' else "archived"
                flash(f'Job posting {status_msg} successfully!', 'success')
                return redirect(url_for('job_postings'))
            
            position = request.form.get('position', '').strip()
            description = request.form.get('description', '').strip()
            location = request.form.get('location', '').strip()
            experience = request.form.get('experience', '').strip()
            expiry_date = request.form.get('expiry_date', '').strip()
            
            if not all([position, description, location, experience, expiry_date]):
                flash('All fields are required!', 'error')
                return redirect(url_for('job_postings'))
            
            cursor.execute("""
                INSERT INTO job_posts 
                (recruiter_id, position, description, location, experience, expiry_date)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (session['user_id'], position, description, location, experience, expiry_date))
            
            cursor.execute("""
                UPDATE recruiter_analytics 
                SET jobs_posted = jobs_posted + 1
                WHERE user_id = %s
            """, (session['user_id'],))
            
            conn.commit()
            flash('Job posted successfully!', 'success')
            return redirect(url_for('job_postings'))
        
        # Modified query to compute status in SQL
        cursor.execute("""
            SELECT *, 
                   CASE 
                       WHEN expiry_date < CURDATE() THEN 'expired'
                       ELSE status
                   END as display_status
            FROM job_posts 
            WHERE recruiter_id = %s
            ORDER BY posted_at DESC
        """, (session['user_id'],))
        jobs = cursor.fetchall()
        
        # Get application counts for each job
        job_applications = {}
        cursor.execute("""
            SELECT job_id, status, COUNT(*) as count 
            FROM job_applications 
            WHERE job_id IN (SELECT id FROM job_posts WHERE recruiter_id = %s)
            GROUP BY job_id, status
        """, (session['user_id'],))
        
        for row in cursor.fetchall():
            if row['job_id'] not in job_applications:
                job_applications[row['job_id']] = {'pending': 0, 'accepted': 0, 'rejected': 0}
            job_applications[row['job_id']][row['status']] = row['count']
        
    except Error as e:
        flash(f'Error processing job post: {str(e)}', 'error')
        return redirect(url_for('job_postings'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return render_template('job_postings.html', 
                         jobs=jobs, 
                         job_applications=job_applications)

@app.route('/recruiter/job/<int:job_id>/applicants')
@login_required
@role_required('recruiter')
def job_applicants(job_id):
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('job_postings'))
            
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id, position FROM job_posts 
            WHERE id = %s AND recruiter_id = %s
        """, (job_id, session['user_id']))
        job = cursor.fetchone()
        
        if not job:
            flash('Job not found or access denied!', 'error')
            return redirect(url_for('job_postings'))
        
        cursor.execute("""
            SELECT ja.*, u.name, u.email, js.education, js.skills,
                   CASE 
                       WHEN jp.expiry_date < CURDATE() THEN 'expired'
                       ELSE ja.status
                   END as display_status
            FROM job_applications ja
            JOIN users u ON ja.applicant_id = u.id
            LEFT JOIN jobseeker_profiles js ON u.id = js.user_id
            JOIN job_posts jp ON ja.job_id = jp.id
            WHERE ja.job_id = %s
            ORDER BY ja.applied_at DESC
        """, (job_id,))
        applicants = cursor.fetchall()
        
    except Error as e:
        flash(f'Error fetching applicants: {str(e)}', 'error')
        return redirect(url_for('job_postings'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return render_template('job_applicants.html', applicants=applicants, job=job)

@app.context_processor
def inject_unread_notifications():
    if 'user_id' in session and session.get('role') == 'jobseeker':
        try:
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT COUNT(*) as unread_count 
                    FROM jobseeker_notifications
                    WHERE user_id = %s AND is_read = FALSE
                """, (session['user_id'],))
                result = cursor.fetchone()
                return {'unread_notifications': result['unread_count'] if result else 0}
        except Error as e:
            print(f"Error fetching unread notifications: {e}")
            return {'unread_notifications': 0}
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()
    return {'unread_notifications': 0}

@app.route('/recruiter/update-application-status/<int:application_id>', methods=['POST'])
@login_required
@role_required('recruiter')
def update_application_status(application_id):
    new_status = request.form.get('status', '').strip()
    
    if not new_status or new_status not in ['accepted', 'rejected']:
        flash('Invalid status provided!', 'error')
        return redirect(request.referrer or url_for('job_postings'))
    
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(request.referrer or url_for('job_postings'))
            
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT ja.id, ja.applicant_id, ja.job_id, jp.position
            FROM job_applications ja
            JOIN job_posts jp ON ja.job_id = jp.id
            WHERE ja.id = %s AND jp.recruiter_id = %s
        """, (application_id, session['user_id']))
        application = cursor.fetchone()
        
        if not application:
            flash('Application not found or access denied!', 'error')
            return redirect(url_for('job_postings'))
        
        cursor.execute("""
            UPDATE job_applications 
            SET status = %s
            WHERE id = %s
        """, (new_status, application_id))
        
        message = f"Your application for {application['position']} has been {new_status}"
        cursor.execute("""
            INSERT INTO jobseeker_notifications 
            (user_id, application_id, message)
            VALUES (%s, %s, %s)
        """, (application['applicant_id'], application_id, message))
        
        if new_status == 'accepted':
            cursor.execute("""
                UPDATE recruiter_analytics 
                SET applications_accepted = applications_accepted + 1
                WHERE user_id = %s
            """, (session['user_id'],))
            
            cursor.execute("""
                UPDATE jobseeker_analytics 
                SET applications_accepted = applications_accepted + 1
                WHERE user_id = %s
            """, (application['applicant_id'],))
        elif new_status == 'rejected':
            cursor.execute("""
                UPDATE recruiter_analytics 
                SET applications_rejected = applications_rejected + 1
                WHERE user_id = %s
            """, (session['user_id'],))
            
            cursor.execute("""
                UPDATE jobseeker_analytics 
                SET applications_rejected = applications_rejected + 1
                WHERE user_id = %s
            """, (application['applicant_id'],))
        
        conn.commit()
        flash(f'Application status updated to {new_status}!', 'success')
        
    except Error as e:
        conn.rollback()
        flash(f'Error updating application status: {str(e)}', 'error')
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return redirect(request.referrer or url_for('job_postings'))

@app.route('/recruiter/notifications')
@login_required
@role_required('recruiter')
def recruiter_notifications():
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('recruiter_dashboard'))
            
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT rn.*, ja.job_id, jp.position, u.name as applicant_name
            FROM recruiter_notifications rn
            JOIN job_applications ja ON rn.application_id = ja.id
            JOIN job_posts jp ON ja.job_id = jp.id
            JOIN users u ON ja.applicant_id = u.id
            WHERE rn.user_id = %s
            ORDER BY rn.created_at DESC
        """, (session['user_id'],))
        notifications = cursor.fetchall()
        
        cursor.execute("""
            UPDATE recruiter_notifications 
            SET is_read = TRUE
            WHERE user_id = %s AND is_read = FALSE
        """, (session['user_id'],))
        conn.commit()
        
    except Error as e:
        flash(f'Error fetching notifications: {str(e)}', 'error')
        return redirect(url_for('recruiter_dashboard'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return render_template('recruiter_notifications.html', notifications=notifications, role='recruiter')

@app.route('/recruiter/analytics')
@login_required
@role_required('recruiter')
def recruiter_analytics():
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'error')
            return redirect(url_for('recruiter_dashboard'))
            
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM recruiter_analytics WHERE user_id = %s", (session['user_id'],))
        analytics = cursor.fetchone()
        
        if analytics:
            if analytics['total_applications'] > 0:
                analytics['acceptance_rate'] = round(
                    (analytics['applications_accepted'] / analytics['total_applications']) * 100, 
                    2
                )
            else:
                analytics['acceptance_rate'] = 0
            
            cursor.execute("""
                SELECT jp.id, jp.position, COUNT(ja.id) as applications,
                       SUM(CASE WHEN ja.status = 'accepted' THEN 1 ELSE 0 END) as accepted,
                       SUM(CASE WHEN ja.status = 'rejected' THEN 1 ELSE 0 END) as rejected
                FROM job_posts jp
                LEFT JOIN job_applications ja ON jp.id = ja.job_id
                WHERE jp.recruiter_id = %s
                GROUP BY jp.id
                ORDER BY jp.posted_at DESC
                LIMIT 5
            """, (session['user_id'],))
            job_performance = cursor.fetchall()
            analytics['job_performance'] = job_performance
        
    except Error as e:
        flash(f'Error fetching analytics: {str(e)}', 'error')
        return redirect(url_for('recruiter_dashboard'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    
    return render_template('recruiter_analytics.html', analytics=analytics)

if __name__ == '__main__':
    app.run(debug=True)