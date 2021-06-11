from flask import Flask ,request , jsonify , make_response , render_template
from flask.globals import g 
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta , date
from functools import wraps
from flask_oidc import OpenIDConnect
from werkzeug.utils import redirect
from models import *
from config import *
import jwt
import requests
import json


app=Flask(__name__,template_folder="./templates")

app.config.update({
    'SECRET_KEY': 'SomethingNotEntirelySecret',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': './client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'nwclient',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    'OIDC_TOKEN_TYPE_HINT': 'access_token'
})

oidc = OpenIDConnect(app)


@app.route('/')
def LandingPage():
    if oidc.user_loggedin:
        return render_template("landing.html")
    else:
        return render_template("login.html")


@app.route('/private')
@oidc.require_login
def KeycloakLogin():
    """Example for protected endpoint that extracts private information from the OpenID Connect id_token.
       Uses the accompanied access_token to access a backend service.
    """
    info = oidc.user_getinfo(['preferred_username', 'email', 'sub'])
    username = info.get('preferred_username')
    email = info.get('email')
    user_id = info.get('sub')

    if user_id in oidc.credentials_store:
        try:
            from oauth2client.client import OAuth2Credentials
            access_token = OAuth2Credentials.from_json(oidc.credentials_store[user_id]).access_token
            print('access_token=<%s>' % access_token)
            headers = {'Authorization': 'Bearer %s' % (access_token)}
            # YOLO
            greeting = requests.get('http://localhost:8080/*', headers=headers).text
        except:
            print("Could not access greeting-service")
            greeting = "Hello %s" % username
        info = oidc.user_getinfo(['preferred_username', 'email', 'sub'])
    username=info.get('preferred_username').title()
    return render_template("landing.html",username=username)

@app.route('/api', methods=['POST'])
@oidc.accept_token(require_token=True, scopes_required=['openid'])
def hello_api():
    """OAuth 2.0 protected API endpoint accessible via AccessToken"""
    return json.dumps({'hello': 'Welcome %s' % g.oidc_token_info['sub']})

@app.route('/logout')
def logout():
    """Performs local logout by removing the session cookie."""

    oidc.logout()
    return render_template('login.html')

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
def UserView(id):
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
def UserUpdate(id):
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
def UsereDelete(id):
    user_record = Users.query.get_or_404(id)
    if request.method == 'DELETE':
        db.session.delete(user_record)
        db.session.commit()
        return {"message": f"record has been deleted successfully","status":200}


#insert new employee data related script
@app.route("/employee/create", methods=['POST'])
def EmployeeCreation():
    if oidc.user_loggedin:
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
    else:
        return render_template("login.html")

#display specific employee data related script
@app.route("/employee/<int:eid>/view", methods=['GET'])
def EmployeeView(eid):
    if oidc.user_loggedin:
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
    else:
        return render_template("login.html")


#update specific employee data related script
@app.route("/employee/<int:eid>/update", methods=['PUT'])
def EmployeeUpdate(eid):
    if oidc.user_loggedin:
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
    else:
        return render_template("login.html")

#delete specific employee data related script
@app.route("/employee/<int:eid>/delete", methods=['DELETE'])
def EmployeeDelete(eid):
    if oidc.user_loggedin:
        emp_record = Employee.query.get_or_404(eid)
        if request.method == 'DELETE':
            db.session.delete(emp_record)
            db.session.commit()
            return {"message": f"record has been deleted successfully","status":200}

    else:
        return render_template("login.html")

# -------------------------
#insert new company data related script
@app.route("/company/create", methods=['POST'])
def CompanyCreation():
    if oidc.user_loggedin:
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
    else:
        return render_template("login.html")

#display specific company data related script
@app.route("/company/<int:eid>/view", methods=['GET'])
def CompanyView(eid):
    if oidc.user_loggedin:
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
    else:
        return render_template("login.html")

#update specific company data related script
@app.route("/company/<int:eid>/update", methods=['PUT'])
def CompanyUpdate(eid):
    if oidc.user_loggedin:
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
    else:
        return render_template("login.html")

#delete specific company data related script
@app.route("/company/<int:cid>/delete", methods=['DELETE'])
def CompanyDelete(cid):
    if oidc.user_loggedin:
        cmp_record = Company.query.get_or_404(cid)
        if request.method == 'DELETE':
            db.session.delete(cmp_record)
            db.session.commit()
            return {"message": f"record has been deleted successfully","status":200}
    else:
        return render_template("login.html")