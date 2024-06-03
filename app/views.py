# views.py

from flask import render_template, url_for, flash, redirect, request
from app import app, db, bcrypt
from flask_login import login_user, current_user, logout_user, login_required
from app.utils import is_superadmin, is_admin, is_user, has_permission
from app.models import User, Role, Permission
from app.forms import RoleForm, UserForm, LoginForm

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = UserForm()
    form.role_name.choices = [(role.id, role.role_name) for role in Role.query.all()]
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        role_id = form.role_name.data

        role = Role.query.get(role_id)
        if not role:
            flash('Invalid role.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password_hash=hashed_password)
        user.roles.append(role)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

from sqlalchemy.exc import IntegrityError

@app.route('/manage_roles', methods=['GET', 'POST'])
@login_required
def manage_roles():
    if not is_superadmin(current_user):
        flash('Access denied. Only Superadmins can access this page.', 'danger')
        return redirect(url_for('home'))

    form = RoleForm()
    form.permissions.choices = [(perm.id, perm.permission_name) for perm in Permission.query.all()]

    if form.validate_on_submit():
        role_name = form.role_name.data
        permissions = form.permissions.data

        existing_role = Role.query.filter_by(role_name=role_name).first()
        if existing_role:
            flash('Role already exists.', 'danger')
        else:
            role = Role(role_name=role_name)
            for perm_id in permissions:
                permission = Permission.query.get(perm_id)
                if permission:
                    role.permissions.append(permission)
            db.session.add(role)
            try:
                db.session.commit()
                flash('Role added successfully.', 'success')
            except IntegrityError:
                db.session.rollback()
                flash('An error occurred while adding the role.', 'danger')

    roles = Role.query.all()
    permissions = Permission.query.all()
    return render_template('manage_roles.html', form=form, roles=roles, permissions=permissions)


@app.route('/user_dashboard')
@login_required
def user_dashboard():
    return render_template('user.html')

@app.route("/admin_dashboard")
@login_required
def admin_dashboard():
    # Check if the current user is a superadmin or an admin
    if not is_superadmin(current_user) and not is_admin(current_user):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))

    # Retrieve only users with the role name "User" from the database
    users = User.query.filter(User.roles.any(Role.role_name == 'User')).all()
    return render_template('admin_dashboard.html', users=users)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not is_superadmin(current_user):
        flash('Access denied. Only Superadmins can delete users.', 'danger')
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))