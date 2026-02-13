"""
Application Configuration
=========================
Central configuration for the Phishing Detection Flask app.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'phishing-detector-secret-key-2026')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-super-secret-key-ph1sh')
    JWT_EXPIRY_HOURS = 24

    # Database
    DATABASE_PATH = os.path.join(BASE_DIR, 'database', 'users.db')

    # Dataset
    DATASET_PATH = os.path.join(BASE_DIR, 'Phishing_Legitimate_full.csv')

    # Model
    MODEL_DIR = os.path.join(BASE_DIR, 'saved_model')
    MODEL_PATH = os.path.join(MODEL_DIR, 'phishing_model.h5')
    SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')
    HISTORY_PATH = os.path.join(MODEL_DIR, 'training_history.json')
    IMPORTANCE_PATH = os.path.join(MODEL_DIR, 'feature_importance.json')

    # Training Hyperparameters
    EPOCHS = 20
    BATCH_SIZE = 64
    VALIDATION_SPLIT = 0.2
    TEST_SPLIT = 0.2
    EARLY_STOPPING_PATIENCE = 5
    RANDOM_SEED = 42

    # Feature columns (all 48 features from the dataset)
    FEATURE_COLUMNS = [
        'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
        'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
        'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
        'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress',
        'DomainInSubdomains', 'DomainInPaths', 'HttpsInHostname',
        'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath',
        'NumSensitiveWords', 'EmbeddedBrandName', 'PctExtHyperlinks',
        'PctExtResourceUrls', 'ExtFavicon', 'InsecureForms',
        'RelativeFormAction', 'ExtFormAction', 'AbnormalFormAction',
        'PctNullSelfRedirectHyperlinks', 'FrequentDomainNameMismatch',
        'FakeLinkInStatusBar', 'RightClickDisabled', 'PopUpWindow',
        'SubmitInfoToEmail', 'IframeOrFrame', 'MissingTitle',
        'ImagesOnlyInForm', 'SubdomainLevelRT', 'UrlLengthRT',
        'PctExtResourceUrlsRT', 'AbnormalExtFormActionR',
        'ExtMetaScriptLinkRT', 'PctExtNullSelfRedirectHyperlinksRT'
    ]

    TARGET_COLUMN = 'CLASS_LABEL'
