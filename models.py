from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()


# User Models DB design
class Users(db.Model):
        __tablename__ = 'users'

        id = db.Column(db.Integer, primary_key=True, autoincrement=True)
        first_name = db.Column(db.String(100), nullable=False)
        last_name = db.Column(db.String(100), nullable=False)
        password_hashed = db.Column(db.String(100),nullable=False)
        mobile_no = db.Column(db.String(100),nullable=False, unique=True)
        email_id = db.Column(db.String(100),nullable=False, unique=True)
        date_created  = db.Column(db.DateTime,  default=db.func.current_timestamp())
        date_modified = db.Column(db.DateTime,  default=db.func.current_timestamp(),
                                                onupdate=db.func.current_timestamp())
        
        def __int__(self, first_name, last_name, password_hashed, mobile_no,email_id):
            self.first_name = first_name
            self.last_name = last_name
            self.password_hashed = password_hashed
            self.mobile_no = mobile_no
            self.email_id = email_id

        def __repr__(self):
            return '{}'.format(self.email_id)




# Employee Models DB design
class Employee(db.Model):
        __tablename__ = 'employees'
        
        eid = db.Column(db.Integer, primary_key=True, autoincrement=True)
        first_name = db.Column(db.String(100), nullable=False )
        last_name = db.Column(db.String(100), nullable=False )
        email_id = db.Column(db.String(100),nullable=False, unique=True)
        mobile_no = db.Column(db.String(100),nullable=False, unique=True)
        date_created  = db.Column(db.DateTime,  default=db.func.current_timestamp())
        date_modified = db.Column(db.DateTime,  default=db.func.current_timestamp(),
                                                onupdate=db.func.current_timestamp())
        
        def __init__(self,first_name, last_name , email_id, mobile_no):
            self.first_name = first_name
            self.last_name = last_name
            self.email_id = email_id
            self.mobile_no = mobile_no
        
        def __repr__(self):
            return '<Employee Name --> {}-{}>'.format(self.first_name , self.last_name)

# Company Models DB design
class Company(db.Model):
        __tablename__ = 'company'

        cid = db.Column(db.Integer, primary_key=True, autoincrement=True)
        eid = db.Column(db.Integer(), db.ForeignKey('employees.eid', ondelete='CASCADE'))
        company_name = db.Column(db.String(100), nullable=False)
        branch = db.Column(db.String(100), nullable=False)
        department = db.Column(db.String(100), nullable=False)
        ceo = db.Column(db.String(100),nullable=False , unique=True)
        date_created  = db.Column(db.DateTime,  default=db.func.current_timestamp())
        date_modified = db.Column(db.DateTime,  default=db.func.current_timestamp(),
                                                onupdate=db.func.current_timestamp())
        
        def __int__(self, e_id, company_name, branch, department, ceo):
            self.e_id = e_id
            self.company_name = company_name
            self.branch = branch
            self.department = department
            self.ceo = ceo

        def __repr__(self):
            return 'Company Name --> {}'.format(self.company_name)
