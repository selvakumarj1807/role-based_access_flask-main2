# initialize_superadmin.py
from app import create_app, db, bcrypt
from app.models import User, Role, Permission

app = create_app()
app.app_context().push()

def create_superadmin():
    # Create permissions if they don't already exist
    superadmin_permission = Permission.query.filter_by(name='superadmin').first()
    if not superadmin_permission:
        superadmin_permission = Permission(name='superadmin')
        db.session.add(superadmin_permission)

    admin_permission = Permission.query.filter_by(name='admin').first()
    if not admin_permission:
        admin_permission = Permission(name='admin')
        db.session.add(admin_permission)

    user_permission = Permission.query.filter_by(name='user').first()
    if not user_permission:
        user_permission = Permission(name='user')
        db.session.add(user_permission)

    db.session.commit()

    # Create roles and assign permissions if they don't already exist
    superadmin_role = Role.query.filter_by(name='superadmin').first()
    if not superadmin_role:
        superadmin_role = Role(name='superadmin')
        superadmin_role.permissions.extend([superadmin_permission, admin_permission, user_permission])
        db.session.add(superadmin_role)

    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        admin_role = Role(name='admin')
        admin_role.permissions.extend([admin_permission, user_permission])
        db.session.add(admin_role)

    user_role = Role.query.filter_by(name='user').first()
    if not user_role:
        user_role = Role(name='user')
        user_role.permissions.append(user_permission)
        db.session.add(user_role)

    db.session.commit()

    # Create superadmin user if they don't already exist
    superadmin_user = User.query.filter_by(username='superadmin').first()
    if not superadmin_user:
        hashed_password = bcrypt.generate_password_hash('superadminpassword').decode('utf-8')
        superadmin_user = User(username='superadmin', email='superadmin@example.com', password_hash=hashed_password, role=superadmin_role)
        db.session.add(superadmin_user)
        db.session.commit()

    print('Superadmin account and roles created.')

create_superadmin()
