from flask import render_template, url_for, flash, redirect, request
from flask_login import login_user, current_user, logout_user, login_required
from app import app, db
from app.models import User

@app.route("/admin")
@login_required
def admin_dashboard():
    if not current_user.has_permission('view_user'):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))
    return render_template('admin_dashboard.html')

@app.route("/create_user", methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.has_permission('create_user'):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))
    # Logic for creating a user
    return render_template('create_user.html')

# Other routes and logic
