# utils.py

from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user

def is_superadmin(user):
    return any(role.role_name == 'Superadmin' for role in user.roles)

def is_admin(user):
    return any(role.role_name == 'Admin' for role in user.roles)

def is_user(user):
    return any(role.role_name == 'User' for role in user.roles)

def has_permission(user, perm_name):
    return any(perm.permission_name == perm_name for role in user.roles for perm in role.permissions)

def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not any(role.role_name == role_name for role in current_user.roles):
                flash('Access denied. You do not have the required role to access this page.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def permission_required(perm_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not has_permission(current_user, perm_name):
                flash('Access denied. You do not have the required permission to access this page.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
