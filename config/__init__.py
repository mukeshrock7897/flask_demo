import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from views import app
from flask_cors import CORS
from dotenv import load_dotenv


db = SQLAlchemy()
migrate = Migrate()
CORS(app)

def create_app():
    load_dotenv(".env")
    #develpment database credentials
    if os.environ.get('ENIVORNMENT').upper()=='DEV':
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
        app.config['SECRET_KEY']="dfsafuiasjeuirfsej"
        app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://{username}:{password}@{host}:{port}/{database}'.format(
                    username = "mukeshrock7897",
                    password = "7800195472mukMUK",
                    host = "database-1.ce8jgqqgaafk.us-east-1.rds.amazonaws.com",
                    port = "5432",
                    database = "botzerdatabase"
                    )
        db.init_app(app)
        migrate.init_app(app, db)
        print("This environment name is :::::::::DEV")
        return app

    #testing database credentials
    elif os.environ.get('ENIVORNMENT').upper()=='TEST':
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
        app.config['SECRET_KEY']="dfsafuiasjeuirfsej"
        app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://{username}:{password}@{host}:{port}/{database}'.format(
                    username = "mukeshrock7897",
                    password = "7800195472mukMUK",
                    host = "database-1.ce8jgqqgaafk.us-east-1.rds.amazonaws.com",
                    port = "5432",
                    database = "botzerdatabase"
                    )
        db.init_app(app)
        migrate.init_app(app, db)
        print("This environment name is :::::::::TEST")
        return app

    #production database credentials
    elif os.environ.get('ENIVORNMENT').upper()=='PROD':
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
        app.config['SECRET_KEY']="dfsafuiasjeuirfsej"
        app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://{username}:{password}@{host}:{port}/{database}'.format(
                    username = "mukeshrock7897",
                    password = "7800195472mukMUK",
                    host = "database-1.ce8jgqqgaafk.us-east-1.rds.amazonaws.com",
                    port = "5432",
                    database = "botzerdatabase"
                    )
        db.init_app(app)
        migrate.init_app(app, db)
        print("This environment name is :::::::::PROD")
        return app