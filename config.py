import os
from dotenv import load_dotenv

# .env file ka path set karna
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    """Poore application ki configuration settings."""
    
    # 1. Secret Key
    # .env file se SECRET_KEY ko load karega
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ek-bahut-hi-random-default-key'

    # 2. Database Configuration
    # .env file se DATABASE_URL ko load karega
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///default.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 3. YEH RAHI AAPKI MAIL SETTINGS
    # Yeh saari details .env file se uthayega
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') == 'True'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')