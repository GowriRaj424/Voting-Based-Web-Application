class Config:
    SECRET_KEY = 'your_secret_key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///polls.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    LOGIN_MANAGER_LOGIN_VIEW = 'login'
