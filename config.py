import os
from datetime import timedelta

class Config:
    # Basic Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///crime_database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File Upload Configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/images')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    
    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    
    # Security Configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY') or 'csrf-secret-key'
    
    # User Roles
    USER_ROLES = ['admin', 'police', 'user']
    
    # Crime Report Status Options
    CRIME_STATUS_OPTIONS = ['pending', 'investigating', 'resolved']
    
    # Pagination Configuration
    CRIMINALS_PER_PAGE = 10
    REPORTS_PER_PAGE = 20

class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///crime_database.db'

class ProductionConfig(Config):
    DEBUG = False
    # Use environment variables for sensitive data in production
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY')

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test_database.db'
    WTF_CSRF_ENABLED = False

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}