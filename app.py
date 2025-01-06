from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from forms import RegistrationForm, LoginForm
from models import db, User
from flask_migrate import Migrate
from flask_wtf import CSRFProtect

app = Flask(__name__)

app.config['SECRET_KEY'] = '12ss'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://username:@localhost/user_management'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
csrf = CSRFProtect(app)



@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))  
    return redirect(url_for('login'))  

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            user = User(
                username=form.username.data,
                email=form.email.data,
                role=request.form.get('role')  # Get the selected role
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()  # Rollback in case of error
            flash(f'Registration failed: {str(e)}', 'danger')
    return render_template('register.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for ('login'))
    current_user = User.query.get(session['user_id'])
    if current_user.role != 'admin':
        flash('Access denied. You can only view the user list.', 'danger')
        users = User.query.all()  # Allow users to see the list of users
        return render_template('dashboard.html', users=users)
    users = User.query.all()  # Admin can see all users
    return render_template('dashboard.html', users=users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            session['user_id'] = user.id
            if request.form.get('remember'):
                session.permanent = True  
            flash(' Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter((User .username == form.username.data) | (User .email == form.email.data)).first()
        if existing_user:
            flash('Username or email already exists. Please choose a different one.', 'danger')
            return redirect(url_for('add_user'))

        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('User  added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = RegistrationForm(obj=user)
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        if form.password.data:
            user.set_password(form.password.data)
        db.session.commit()
        flash('User  updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_user.html', form=form, user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User  deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/manage_roles', methods=['GET', 'POST']) 
def manage_roles(): 
    if 'user_id' not in session: return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    if current_user.role != 'admin':
        flash('Access denied. You have been logged out.', 'danger')
        session.pop('user_id', None)
        return redirect(url_for('login')) 
    users = User.query.all()
    return render_template('manage_roles.html', users=users)


if __name__ == '__main__':
    app.run(debug=True)
