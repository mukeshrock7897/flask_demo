import os
from flask import Flask
from flask_script import Manager, Server
from flask_migrate import Migrate, MigrateCommand
from flask_sqlalchemy import SQLAlchemy
from config import *
from models import *


manager = Manager(create_app)
manager.add_command('db', MigrateCommand)
if __name__ == '__main__':
    manager.add_command("runserver", Server(
        use_reloader = True,
        host = '127.0.0.1',
        port=5000

        ) )
    manager.run()
