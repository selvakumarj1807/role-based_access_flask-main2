from flask import render_template, url_for, flash, redirect, request
from app import app, db
from flask_login import login_user, current_user, logout_user, login_required
from app.utils import is_superadmin, is_admin, is_user, has_permission, permissions_required
from app.models import User, Role, Permission
from app.forms import RoleForm, UserForm, LoginForm

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
   # if current_user.is_authenticated:
       # return redirect(url_for('home'))
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

        user = User(username=username, email=email)
        user.set_password(password)
        user.roles.append(role)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('manage_roles'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
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
@permissions_required('manage_roles')  # This is the permission name you want to check
def manage_roles():
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

    
    users = User.query.all()
    user_data = []
    for user in users:
        roles = [role.role_name for role in user.roles]
        user_data.append({
            'user': user,
            'roles': roles
        })
    roles = Role.query.all()
    permissions = Permission.query.all()
    
    return render_template('manage_roles.html', form=form, roles=roles, permissions=permissions, users=user_data)

@app.route('/user_dashboard')
@login_required
@permissions_required('user_dashboard')  # This is the permission name you want to check
def user_dashboard():
    return render_template('user.html')

@app.route("/admin_dashboard")
@login_required
@permissions_required('admin_dashboard')  # This is the permission name you want to check
def admin_dashboard():
    # Retrieve users with the role name "User" from the database
    users = User.query.filter(User.roles.any(Role.role_name == 'User')).all()

    # Prepare a list of dictionaries containing user info and their role names
    user_data = []
    for user in users:
        roles = [role.role_name for role in user.roles]
        user_data.append({
            'user': user,
            'roles': roles
        })

    return render_template('admin_dashboard.html', users=user_data)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@permissions_required('admin_dashboard', 'manage_roles')  # This is the permission name you want to check
def delete_user(user_id):
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_role/<int:role_id>', methods=['POST'])
@login_required
@permissions_required('admin_dashboard', 'manage_roles')
def delete_role(role_id):
    role = Role.query.get_or_404(role_id)
    # Collect all associated permissions
    permissions_to_delete = role.permissions[:]
    
    db.session.delete(role)
    db.session.commit()

    # Delete permissions that are no longer associated with any roles
    for permission in permissions_to_delete:
        if not permission.roles:
            db.session.delete(permission)
    db.session.commit()

    flash('Role and its associated permissions deleted successfully.', 'success')
    return redirect(url_for('manage_roles'))