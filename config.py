# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'аokskpDMKMDMKAkmadlmMLKdmaDS'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://mrln:password@localhost/perfomance_predict_service'
    SQLALCHEMY_TRACK_MODIFICATIONS = False