from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from config import Config # Yeh file aapke .env se settings load karti hai

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXT = {'png','jpg','jpeg','gif','pdf'}

# --- Models ---

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    attachment = db.Column(db.String(300))
    status = db.Column(db.String(50), default='Pending')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='complaints')

# --- Login Manager ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXT

# --- Main Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'warning')
            return redirect(url_for('register'))
        user = User(name=name, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password) and not user.is_admin:
            login_user(user)
            flash('Logged in successfully', 'success')
            return redirect(url_for('student_dashboard'))
        flash('Invalid student credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('index'))

# --- Student Routes ---

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    complaints = Complaint.query.filter_by(user_id=current_user.id).order_by(Complaint.created_at.desc()).all()
    return render_template('student_dashboard.html', complaints=complaints)

@app.route('/student/complaint/new', methods=['GET','POST'])
@login_required
def new_complaint():
    if current_user.is_admin:
        flash('Admins cannot submit complaints here', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        file = request.files.get('attachment')
        filename = None
        
        if file and file.filename != '' and allowed_file(file.filename):
            filename = f"{int(datetime.utcnow().timestamp())}_{file.filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        c = Complaint(title=title, description=description, attachment=filename, user_id=current_user.id)
        db.session.add(c)
        db.session.commit()
        
        # Email to Admin
        try:
            admin_email = app.config.get('ADMIN_EMAIL')
            if admin_email:
                msg = Message(subject=f"New Complaint: {title}", recipients=[admin_email])
                msg.body = f"New complaint by {current_user.name} ({current_user.email})\n\nTitle: {title}\n\n{description}"
                mail.send(msg)
        except Exception as e:
            print('Mail to admin failed:', e)
            
        flash('Complaint submitted', 'success')
        return redirect(url_for('student_dashboard'))
    
    return render_template('complaint_form.html')

# --- Admin Routes ---

@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, is_admin=True).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Admin logged in', 'success')
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('student_dashboard'))
    
    total = Complaint.query.count()
    pending = Complaint.query.filter_by(status='Pending').count()
    inprog = Complaint.query.filter_by(status='In Progress').count()
    resolved = Complaint.query.filter_by(status='Resolved').count()
    recent = Complaint.query.order_by(Complaint.created_at.desc()).limit(10).all()
    students = User.query.filter_by(is_admin=False).count()
    
    return render_template('admin_dashboard.html', total=total, pending=pending, inprog=inprog, resolved=resolved, recent=recent, students=students)

@app.route('/admin/complaints')
@login_required
def admin_manage_complaints():
    if not current_user.is_admin:
        return redirect(url_for('student_dashboard'))
    
    q = request.args.get('q','')
    if q:
        complaints = Complaint.query.filter(Complaint.title.contains(q) | Complaint.description.contains(q)).order_by(Complaint.created_at.desc()).all()
    else:
        complaints = Complaint.query.order_by(Complaint.created_at.desc()).all()
    
    return render_template('manage_complaints.html', complaints=complaints, q=q)


# --- YEH FUNCTION UPDATE KIYA GAYA HAI ---
@app.route('/admin/complaint/<int:cid>/update', methods=['POST'])
@login_required
def admin_update_complaint(cid):
    if not current_user.is_admin:
        return redirect(url_for('student_dashboard'))
    
    c = Complaint.query.get_or_404(cid)
    status = request.form.get('status') # Naya status jo admin ne select kiya
    
    # Agar status change hua hai toh hi action lein
    if status and c.status != status: 
        c.status = status
        db.session.commit()
        
        # Ab check karein ki naya status 'Resolved' hai kya
        if status == 'Resolved':
            # --- YEH HAI AAPKA SPECIAL RESOLVED EMAIL ---
            try:
                if c.user and c.user.email:
                    subject = "🎉 Your Complaint Has Been Resolved! — NkTechStudy"
                    body = f"""
Hello {c.user.name},

Good news! Your complaint has been successfully resolved by the administration.

🧾 Complaint Details:
---------------------------------
Title: {c.title}
Description: {c.description}
Status: ✅ Resolved
Date: {datetime.utcnow().strftime('%d-%b-%Y')}

We appreciate your patience and cooperation.
If you face any further issues, feel free to submit a new complaint.

Best Regards,
NkTechStudy Complaint Cell 💙
"""
                    msg = Message(subject=subject, recipients=[c.user.email], body=body)
                    mail.send(msg)
                    flash('Complaint resolved and email sent!', 'success')
            except Exception as e:
                print('Mail failed:', e)
                flash('Complaint resolved, but email failed.', 'warning')
        
        else:
            # --- YEH HAI NORMAL UPDATE EMAIL (In Progress, etc.) ---
            try:
                if c.user and c.user.email:
                    msg = Message(subject=f"Complaint #{c.id} status updated", recipients=[c.user.email])
                    msg.body = f"Hello {c.user.name},\n\nYour complaint '{c.title}' status has been updated to: {c.status}\n\nRegards\nAdmin"
                    mail.send(msg)
                    flash('Complaint status updated.', 'success')
            except Exception as e:
                print('Mail failed:', e)
                flash('Status updated, but email failed.', 'warning')
    
    else:
        flash('No change in status.', 'info')
        
    return redirect(url_for('admin_manage_complaints'))
# --- END OF UPDATED FUNCTION ---


@app.route('/admin/complaint/<int:cid>/delete', methods=['POST'])
@login_required
def admin_delete_complaint(cid):
    if not current_user.is_admin:
        return redirect(url_for('student_dashboard'))
    c = Complaint.query.get_or_404(cid)
    db.session.delete(c)
    db.session.commit()
    flash('Complaint deleted', 'info')
    return redirect(url_for('admin_manage_complaints'))

@app.route('/admin/students')
@login_required
def admin_manage_students():
    if not current_user.is_admin:
        return redirect(url_for('student_dashboard'))
    students = User.query.filter_by(is_admin=False).order_by(User.created_at.desc()).all()
    return render_template('manage_students.html', students=students)

@app.route('/admin/student/<int:uid>/edit', methods=['GET','POST'])
@login_required
def admin_edit_student(uid):
    if not current_user.is_admin:
        return redirect(url_for('student_dashboard'))
    user = User.query.get_or_404(uid)
    if request.method == 'POST':
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        db.session.commit()
        flash('Student updated', 'success')
        return redirect(url_for('admin_manage_students'))
    return render_template('edit_student.html', user=user)

# --- Utility Routes ---

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/stats.json')
@login_required
def stats():
    if not current_user.is_admin:
        return jsonify({'error':'forbidden'}), 403
    
    today = datetime.utcnow().date()
    labels = []
    counts = []
    
    for i in range(6, -1, -1):
        d = today - timedelta(days=i)
        labels.append(d.strftime('%Y-%m-%d'))
        start = datetime(d.year, d.month, d.day)
        end = start + timedelta(days=1)
        c = Complaint.query.filter(Complaint.created_at >= start, Complaint.created_at < end).count()
        counts.append(c)
        
    return jsonify({'labels': labels, 'counts': counts})

# --- Startup Function ---

def create_tables_and_default_admin():
    db.create_all()
    # Default admin email from config
    admin_email = app.config.get('ADMIN_EMAIL', 'admin@system.com') 
    admin_pass = 'admin123' # Aap isey badal sakte hain
    
    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        admin = User(name='Site Admin', email=admin_email, is_admin=True)
        admin.set_password(admin_pass)
        db.session.add(admin)
        try:
            db.session.commit()
            print(f'Default admin created: {admin_email} / Pass: {admin_pass}')
        except Exception as e:
            db.session.rollback()
            print('Could not create admin:', e)

# --- Run App ---

if __name__ == '__main__':
    with app.app_context():
        create_tables_and_default_admin()
    
    app.run(debug=True)