import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', '706e29c5da4fb111f2caeccce8a128101f5aba1c0a1f6cac')
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'mysql+pymysql://root:@localhost:3306/access_rolebased')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
