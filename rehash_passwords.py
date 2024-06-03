# rehash_passwords.py

from app import app, db
from app.models import User
from flask_bcrypt import generate_password_hash

with app.app_context():
    users = User.query.all()
    for user in users:
        # If the password_hash field is empty or not hashed properly, rehash it
        if not user.password_hash or not user.password_hash.startswith('pbkdf2:sha256'):
            new_password = 'defaultpassword'  # or another secure default password
            user.password_hash = generate_password_hash(new_password).decode('utf-8')
            db.session.add(user)
    db.session.commit()
