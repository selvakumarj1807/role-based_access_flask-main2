from app import app, db
from app.models import Role, User, Permission

def create_roles_and_permissions():
    roles = ['Superadmin', 'Admin', 'User']
    permissions = {
        'Superadmin': ['manage_roles', 'admin_dashboard', 'user_dashboard'],
        'Admin': ['admin_dashboard', 'user_dashboard'],
        'User': ['user_dashboard']
    }

    for role_name in roles:
        role = Role.query.filter_by(role_name=role_name).first()
        if not role:
            role = Role(role_name=role_name)
            db.session.add(role)

    db.session.commit()  # Commit after adding all roles to ensure roles are available

    for role_name, perms in permissions.items():
        role = Role.query.filter_by(role_name=role_name).first()
        for perm_name in perms:
            permission = Permission.query.filter_by(permission_name=perm_name).first()
            if not permission:
                permission = Permission(permission_name=perm_name)
                db.session.add(permission)
            if permission not in role.permissions:
                role.permissions.append(permission)

    db.session.commit()  # Commit after adding all permissions

def create_superadmin_user():
    superadmin_role = Role.query.filter_by(role_name='Superadmin').first()
    superadmin_user = User.query.filter_by(username='superadmin').first()
    if not superadmin_user:
        superadmin_user = User(username='superadmin', email='superadmin@example.com')
        superadmin_user.set_password('superadminpassword')
        superadmin_user.roles.append(superadmin_role)
        db.session.add(superadmin_user)
        db.session.commit()

    print("Superadmin role and user created successfully!")

if __name__ == "__main__":
    with app.app_context():
        create_roles_and_permissions()
        create_superadmin_user()
