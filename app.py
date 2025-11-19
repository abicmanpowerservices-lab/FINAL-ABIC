import os, datetime, secrets
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, current_user, login_required, UserMixin

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'devsecret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///payroll.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='employee')

class Payroll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    period = db.Column(db.String(120))
    monthly_base = db.Column(db.Numeric(12,2), default=0)
    total_earnings = db.Column(db.Numeric(12,2), default=0)
    total_deductions = db.Column(db.Numeric(12,2), default=0)
    netpay = db.Column(db.Numeric(12,2), default=0)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

# Initialize DB and create admin
@app.before_first_request
def init_db():
    db.create_all()
    admin_email = os.environ.get('ADMIN_EMAIL', 'abicmanpowerservices@gmail.com')
    admin_pw = os.environ.get('ADMIN_PASSWORD', 'admin123')
    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        u = User(full_name='ABIC Admin', email=admin_email, password=generate_password_hash(admin_pw), role='admin')
        db.session.add(u)
        db.session.commit()
        print('Created admin user:', admin_email)

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('employee_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        email = request.form['email'].strip()
        pw = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, pw):
            login_user(user)
            flash('Logged in', 'success')
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('login'))

# Admin views
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    total_employees = User.query.filter(User.role!='admin').count()
    total_payrolls = Payroll.query.count()
    recent = Payroll.query.order_by(Payroll.created_at.desc()).limit(5).all()
    return render_template('admin/dashboard.html', total_employees=total_employees, total_payrolls=total_payrolls, recent=recent)

@app.route('/admin/employees')
@login_required
def admin_employees():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    users = User.query.filter(User.role!='admin').all()
    return render_template('admin/employees.html', users=users)

@app.route('/admin/employees/add', methods=['GET','POST'])
@login_required
def admin_add_employee():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    if request.method=='POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        pw = secrets.token_urlsafe(8)
        user = User(full_name=name, email=email, password=generate_password_hash(pw), role='employee')
        db.session.add(user)
        db.session.commit()
        flash(f'Employee added. Email: {email} Password: {pw} (copy now).', 'success')
        return redirect(url_for('admin_employees'))
    return render_template('admin/add_employee.html')

@app.route('/admin/payrolls')
@login_required
def admin_payrolls():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    payrolls = Payroll.query.order_by(Payroll.created_at.desc()).all()
    employees = {u.id: u for u in User.query.filter(User.role!='admin').all()}
    return render_template('admin/payrolls.html', payrolls=payrolls, employees=employees)

@app.route('/admin/payrolls/add', methods=['GET','POST'])
@login_required
def admin_add_payroll():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    employees = User.query.filter(User.role!='admin').all()
    if request.method=='POST':
        emp_id = int(request.form['employee_id'])
        period = request.form.get('period')
        monthly = request.form.get('monthly_base') or 0
        total_earnings = request.form.get('total_earnings') or 0
        total_deductions = request.form.get('total_deductions') or 0
        netpay = request.form.get('netpay') or 0
        p = Payroll(employee_id=emp_id, period=period, monthly_base=monthly, total_earnings=total_earnings, total_deductions=total_deductions, netpay=netpay)
        db.session.add(p); db.session.commit()
        flash('Payroll added', 'success')
        return redirect(url_for('admin_payrolls'))
    return render_template('admin/add_payroll.html', employees=employees)

# Employee views
@app.route('/employee')
@login_required
def employee_dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    payrolls = Payroll.query.filter_by(employee_id=current_user.id).order_by(Payroll.created_at.desc()).all()
    return render_template('employee/dashboard.html', payrolls=payrolls)

@app.route('/employee/payslip/<int:payroll_id>')
@login_required
def employee_payslip(payroll_id):
    p = Payroll.query.get_or_404(payroll_id)
    if current_user.role!='admin' and p.employee_id != current_user.id:
        flash('Access denied', 'danger'); return redirect(url_for('index'))
    employee = User.query.get(p.employee_id)
    return render_template('employee/payslip.html', p=p, employee=employee)

if __name__=='__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',8080)))
