import os

class Config:
    """Application configuration class"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    # File Upload Configuration
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or 'static/uploads'
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 5 * 1024 * 1024))  # 5MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    
    # QR Code Configuration
    QR_VERSION = 40  # Maximum version for largest capacity
    QR_ERROR_CORRECTION = 'L'  # Lowest error correction for max data
    QR_BOX_SIZE = 6  # Smaller box size for better readability
    QR_BORDER = 4
    QR_MAX_DATA_SIZE = 2953  # QR code v40 max data size
    
    # Database Configuration (for future use)
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///supply_chain.db'
    
    # API Configuration
    API_VERSION = 'v1'
    API_PREFIX = f'/api/{API_VERSION}'
    
    # Business Logic Configuration
    DEFAULT_BATCH_COUNT = 1
    DEFAULT_QUANTITY_PER_BATCH = 1
    
    @staticmethod
    def init_app(app):
        """Initialize Flask app with configuration"""
        app.config.from_object(__class__)
        
        # Ensure upload directory exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
