from flask import Flask ,request , jsonify , make_response
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta , date
from functools import wraps
from models import *
from config import *
import jwt


app=Flask(__name__)


#This script check token related stuffs and used as a decorator for required token validation

def token_required(f):
    @wraps(f) 
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers: 
            token = request.headers['x-access-token'] 
        if not token: 
            return jsonify({'message' : 'Token is missing !!'}), 401
        try: 
            data = jwt.decode(token, app.config.get('SECRET_KEY')) 
            current_user = Users.query.filter_by(email_id = data['email_id']).first() 
        except: 
            return jsonify({'message' : 'Token is invalid !!'}), 401
        return  f(current_user, *args, **kwargs) 
    return decorated 


#checks authentication and authorization of current login user

@app.route('/login', methods =['POST']) 
def login():
    auth = request.authorization 
    if not auth or not auth.username or not auth.password: 
        return make_response({'error':'Could not verify you'},401,{'WWW-Authenticate' : 'Basic realm ="Login required !!"'}) 
    user = Users.query.filter_by(email_id = auth.username.lower()).first() 
    if not user: 
        return make_response( {'error':'username does not exist in our record!!'},404,{'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}) 
    if check_password_hash(user.password_hashed, auth.password): 
        token = jwt.encode({'email_id': user.email_id, 
            'exp' : datetime.utcnow() + timedelta(minutes = 30) 
        }, app.config.get('SECRET_KEY')) 
        return make_response(jsonify({
            'token' : token.decode('UTF-8'),
            'token_expiry_time' : datetime.utcnow() + timedelta(minutes = 30),
            'token_genarted_time'  : datetime.utcnow(),
            "first_name" : user.first_name,
            "last_name" : user.last_name,
            "email_id" : user.email_id,
            "mobile_no" : user.mobile_no,
            "user_id" : user.id
            }), 201)
    return make_response({'error':'invalid username or password, please enter correct credentials'}, 403)



#User create related scripts -------------------------------------------

@app.route('/user/create', methods=['POST'])
def UserCreate():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_user = Users(
                first_name = data['first_name'],
                last_name = data['last_name'],
                password_hashed = generate_password_hash(data['password_hashed']),
                mobile_no = data['mobile_no'],
                email_id = data['email_id'],
                    )
            db.session.add(new_user)
            db.session.commit()
            return {"message": f"user {new_user.first_name +' '+ new_user.last_name} has been created successfully"}
        else:
            return {"error": "The request payload is not correct in JSON format"}


#---------------------------User view related scripts starts --------------------------------------------

@app.route("/user/<int:id>/view", methods=['GET'])
@token_required
def UserView(current_user,id):
    user_record = Users.query.get_or_404(id)
    if request.method == 'GET':
        payload = [
                {
                "user_id": user_record.id,
                "first_name":user_record.first_name,
                "last_name":user_record.last_name,
                "mobile_no":user_record.mobile_no,
                "email_id":user_record.email_id,
                "date_created":user_record.date_created,
                "date_modified":user_record.date_modified,
                }]
        return {"message":"success","status code":200 , "payload": payload}


#---------------------------User update related scripts starts -------------------------------------------

@app.route("/user/<int:id>/update", methods=['PUT'])
@token_required
def UserUpdate(current_user,id):
    user_record = Users.query.get_or_404(id)
    if request.method == 'PUT':
        if request.is_json:
            data = request.get_json()
            user_record.first_name = user_record.first_name if data.get("first_name")==None else data.get("first_name")
            user_record.last_name = user_record.last_name if data.get("last_name")==None else data.get("last_name")
            user_record.mobile_no = user_record.mobile_no if data.get("mobile_no")==None else data.get("mobile_no")
            user_record.email_id = user_record.email_id if data.get("email_id")==None else data.get("email_id")
            db.session.commit()
            return {"message": f"user id {user_record.id} record has been updated successfully","status":200}
        else:
            return {"error": "The request payload is not correct in JSON format"}


# User delete related scripts -----------------------------------------------

@app.route("/user/<int:id>/delete", methods=['DELETE'])
@token_required
def UsereDelete(current_user,id):
    user_record = Users.query.get_or_404(id)
    if request.method == 'DELETE':
        db.session.delete(user_record)
        db.session.commit()
        return {"message": f"record has been deleted successfully","status":200}


#insert new employee data related script
@app.route("/employee/create", methods=['POST'])
@token_required
def EmployeeCreation(current_user):
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_emp_record = Employee(
                    first_name = data['first_name'],
                    last_name = data['last_name'],
                    email_id = data['email_id'],
                    mobile_no = data['mobile_no']
                    )
            db.session.add(new_emp_record)
            db.session.commit()
            return {"message": f"New Employee {new_emp_record.first_name+' '+new_emp_record.last_name} has been created successfully"}
        else:
            return {"error": "The request payload is not correct in JSON format"}

#display specific employee data related script
@app.route("/employee/<int:eid>/view", methods=['GET'])
@token_required
def EmployeeView(current_user,eid):
    emp_record = Employee.query.get_or_404(eid)
    if request.method == 'GET':
        payload = [
                {
                "eid": emp_record.eid,
                "first_name":emp_record.first_name,
                "last_name":emp_record.last_name,
                "email_id":emp_record.email_id,
                "mobile_no":emp_record.mobile_no,
                "date_created":emp_record.date_created,
                "date_modified":emp_record.date_modified,
                }]
        return {"message":"success","status code":200 , "payload": payload}


#update specific employee data related script
@app.route("/employee/<int:eid>/update", methods=['PUT'])
@token_required
def EmployeeUpdate(current_user,eid):
    emp_record = Employee.query.get_or_404(eid)
    if request.method == 'PUT':
        if request.is_json:
            data = request.get_json()
            emp_record.first_name = emp_record.first_name if data.get("first_name")==None else data.get("first_name")
            emp_record.last_name = emp_record.last_name if data.get("last_name")==None else data.get("last_name")
            emp_record.email_id = emp_record.email_id if data.get("email_id")==None else data.get("email_id")
            emp_record.mobile_no = emp_record.mobile_no if data.get("mobile_no")==None else data.get("mobile_no")
            db.session.commit()
            return {"message": f"Employee id {emp_record.eid} record has been updated successfully","status":200}
        else:
            return {"error": "The request payload is not correct in JSON format"}

#delete specific employee data related script
@app.route("/employee/<int:eid>/delete", methods=['DELETE'])
@token_required
def EmployeeDelete(current_user,eid):
    emp_record = Employee.query.get_or_404(eid)
    if request.method == 'DELETE':
        db.session.delete(emp_record)
        db.session.commit()
        return {"message": f"record has been deleted successfully","status":200}


# -------------------------
#insert new company data related script
@app.route("/company/create", methods=['POST'])
@token_required
def CompanyCreation(current_user):
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            new_cmp_record = Company(
                eid = data['eid'],
                company_name = data['company_name'],
                branch = data['branch'],
                department = data['department'],
                ceo = data['ceo']
                    )
            db.session.add(new_cmp_record)
            db.session.commit()
            return {"message": f"New Company {new_cmp_record.company_name} has been created successfully"}
        else:
            return {"error": "The request payload is not correct in JSON format"}

#display specific company data related script
@app.route("/company/<int:eid>/view", methods=['GET'])
@token_required
def CompanyView(current_user,eid):
    cmp_record = Company.query.get_or_404(eid)
    if request.method == 'GET':
        payload = [
                {
                "cid": cmp_record.cid,
                "eid": cmp_record.eid,
                "company_name":cmp_record.company_name,
                "branch":cmp_record.branch,
                "department":cmp_record.department,
                "ceo":cmp_record.ceo,
                "date_created":cmp_record.date_created,
                "date_modified":cmp_record.date_modified,
                }]
        return {"message":"success","status code":200 , "payload": payload}

#update specific company data related script
@app.route("/company/<int:eid>/update", methods=['PUT'])
@token_required
def CompanyUpdate(current_user,eid):
    cmp_record = Company.query.get_or_404(eid)
    if request.method == 'PUT':
        if request.is_json:
            data = request.get_json()
            cmp_record.eid = cmp_record.eid if data.get("eid")==None else data.get("eid")
            cmp_record.company_name = cmp_record.company_name if data.get("company_name")==None else data.get("company_name")
            cmp_record.branch = cmp_record.branch if data.get("branch")==None else data.get("branch")
            cmp_record.department = cmp_record.department if data.get("department")==None else data.get("department")
            cmp_record.ceo = cmp_record.ceo if data.get("ceo")==None else data.get("ceo")
            db.session.commit()
            return {"message": f"Employee id {cmp_record.cid} record has been updated successfully","status":200}
        else:
            return {"error": "The request payload is not correct in JSON format"}

#delete specific company data related script
@app.route("/company/<int:cid>/delete", methods=['DELETE'])
@token_required
def CompanyDelete(current_user,cid):
    cmp_record = Company.query.get_or_404(cid)
    if request.method == 'DELETE':
        db.session.delete(cmp_record)
        db.session.commit()
        return {"message": f"record has been deleted successfully","status":200}