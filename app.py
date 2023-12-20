from flask import Flask, jsonify, request
from flask_cors import CORS
from database import get_database
import sqlite3
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
import json
import os
import datetime
from datetime import timedelta

from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


SECRET_KEY = os.environ.get('SECRET_KEY')


app = Flask(__name__)



app.config["JWT_SECRET_KEY"] = SECRET_KEY  # Change this!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

CORS(app, supports_credentials=True)


jwt = JWTManager(app)






def handle_error(message, status_code):
    response = {
        'error': {
            'message': message,
            'status_code': status_code
        }
    }
    return jsonify(response), status_code


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify({"accessToken":access_token})

@app.route("/adminrefresh", methods=["POST"])
@jwt_required(refresh=True)
def refreshadmin():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    return jsonify({"accessToken":access_token, "role":identity['role']})


@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    return jsonify(foo="bar")


#working
@app.route("/" ,             methods = ["GET"])
@app.route("/showallusers" , methods = ["GET"])
def showallusers():
    allusers = None
    db = get_database()
    user_cursor = db.execute("select * from users")
    allusers = user_cursor.fetchall()
    final_result = []
    for eachuser in allusers:
        user_dict = {}
        user_dict["user_id"]     =     eachuser["user_id"]
        user_dict["full_name"]   =     eachuser["full_name"]
        user_dict["username"]    =     eachuser["username"]
        user_dict["password"]    =     eachuser["password"]
        user_dict["email"]       =     eachuser["email"]
        user_dict["phone"]       =     eachuser["phone"]
        user_dict["institution_organization"] =  eachuser["institution_organization"]
        user_dict["address"]       =     eachuser["address"]
        user_dict["country"]       =     eachuser["country"]
        user_dict["research_department"]       =     eachuser["research_department"]
        user_dict["project_incharge_name"]     =     eachuser["project_incharge_name"]
        user_dict["project_count"]       =     eachuser["project_count"]
        user_dict["samples_count"]       =     eachuser["samples_count"]
        user_dict["credits_remaining"]       =     eachuser["credits_remaining"]
        user_dict["exported"]       =     eachuser["exported"]
        user_dict["storage_used"]       =     eachuser["storage_used"]
        user_dict["registration_date"]       =     eachuser["registration_date"]
        user_dict["registration_approval"]       =     eachuser["registration_approval"]
        user_dict["update_status"]       =     eachuser["update_status"]
        final_result.append(user_dict) 
    return jsonify(final_result)

@app.route("/showalladmins" , methods = ["GET"])
def showalladmins():
    alladmins = None
    db = get_database()
    user_cursor = db.execute("select * from admin where admin_id != 1")
    alladmins = user_cursor.fetchall()
    final_result = []
    for eachadmin in alladmins:
        admin_dict = {}
        admin_dict["admin_id"]     =     eachadmin["admin_id"]
        admin_dict["full_name"]   =     eachadmin["full_name"]
        admin_dict["username"]    =     eachadmin["username"]
        admin_dict["password"]    =     eachadmin["password"]
        admin_dict["email"]       =     eachadmin["email"]
        admin_dict["phone"]       =     eachadmin["phone"]
        admin_dict["address"]       =   eachadmin["address"]
        admin_dict["country"]       =   eachadmin["country"]
        admin_dict["role"]       =      eachadmin["role"]
        final_result.append(admin_dict) 
    return jsonify(final_result)



@app.route("/dashboardcount" , methods = ["GET"])
def dashboardcount():
   
    db = get_database()
    count_user = db.execute("SELECT COUNT(*) FROM users")
    users_count = count_user.fetchone()[0]
    count_project = db.execute("SELECT COUNT(*) FROM projects")
    projects_count = count_project.fetchone()[0]
    count_samples = db.execute("SELECT COUNT(*) FROM samples")
    samples_count = count_samples.fetchone()[0]
    return jsonify({"users_count" : users_count,"projects_count" : projects_count,"samples_count" : samples_count})


@app.route("/projctpermonth", methods=["GET"])
def projct_per_month():
    try:
        projects = None
        with get_database() as db:
            project_cursor = db.execute("""
                SELECT
                    CASE strftime('%m', new_date)
                        WHEN '01' THEN 'Jan'
                        WHEN '02' THEN 'Feb'
                        WHEN '03' THEN 'Mar'
                        WHEN '04' THEN 'Apr'
                        WHEN '05' THEN 'May'
                        WHEN '06' THEN 'Jun'
                        WHEN '07' THEN 'Jul'
                        WHEN '08' THEN 'Aug'
                        WHEN '09' THEN 'Sep'
                        WHEN '10' THEN 'Oct'
                        WHEN '11' THEN 'Nov'
                        WHEN '12' THEN 'Dec'
                        ELSE 'Unknown'
                    END AS month,
                    strftime('%Y', new_date) AS year,
                    COUNT(*) AS project_count
                FROM (
                    SELECT
                        substr(date, 7, 4) || '-' || substr(date, 4, 2) || '-' || substr(date, 1, 2) AS new_date
                    FROM
                        projects
                )
                GROUP BY
                    month, year
                ORDER BY
                    new_date;

            """)

            project_datelimit = db.execute("SELECT MIN(substr(date, 7, 4) || '-' || substr(date, 4, 2) || '-' || substr(date, 1, 2)) AS start_date, MAX(substr(date, 7, 4) || '-' || substr(date, 4, 2) || '-' || substr(date, 1, 2)) AS end_date FROM projects")


            sample_cursor = db.execute(
               """
                SELECT
                    CASE strftime('%m', new_date)
                        WHEN '01' THEN 'Jan'
                        WHEN '02' THEN 'Feb'
                        WHEN '03' THEN 'Mar'
                        WHEN '04' THEN 'Apr'
                        WHEN '05' THEN 'May'
                        WHEN '06' THEN 'Jun'
                        WHEN '07' THEN 'Jul'
                        WHEN '08' THEN 'Aug'
                        WHEN '09' THEN 'Sep'
                        WHEN '10' THEN 'Oct'
                        WHEN '11' THEN 'Nov'
                        WHEN '12' THEN 'Dec'
                        ELSE 'Unknown'
                    END AS month,
                    strftime('%Y', new_date) AS year,
                    COUNT(*) AS sample_count
                FROM (
                    SELECT
                        substr(date, 7, 4) || '-' || substr(date, 4, 2) || '-' || substr(date, 1, 2) AS new_date
                    FROM
                        samples
                )
                GROUP BY
                    month, year
                ORDER BY
                    new_date;


            """)

            project_data = project_cursor.fetchall()
            sample_data = sample_cursor.fetchall()
            project_date = project_datelimit.fetchone()

            project_list = [{"month": row["month"],"year": row["year"], "project_count": row["project_count"]} for row in project_data]
            sample_list = [{"month": row["month"],"year": row["year"], "sample_count": row["sample_count"]} for row in sample_data]



        return jsonify({"project_list":project_list, "sample_list": sample_list, "start_date": project_date["start_date"], "end_date": project_date["end_date"]})
    
    except Exception as e:
        return jsonify({"error": str(e)})


 


@app.route("/showunaprrovedusers" , methods = ["GET"])
def showunaprrovedusers():
    allusers = None
    db = get_database()
    user_cursor = db.execute("select * from users where registration_approval = false")
    allusers = user_cursor.fetchall()
    final_result = []
    for eachuser in allusers:
        user_dict = {}
        user_dict["user_id"]     =     eachuser["user_id"]
        user_dict["full_name"]   =     eachuser["full_name"]
        user_dict["username"]    =     eachuser["username"]
        user_dict["password"]    =     eachuser["password"]
        user_dict["email"]       =     eachuser["email"]
        user_dict["phone"]       =     eachuser["phone"]
        user_dict["institution_organization"] =  eachuser["institution_organization"]
        user_dict["address"]       =     eachuser["address"]
        user_dict["country"]       =     eachuser["country"]
        user_dict["research_department"]       =     eachuser["research_department"]
        user_dict["project_incharge_name"]     =     eachuser["project_incharge_name"]
        user_dict["project_count"]       =     eachuser["project_count"]
        user_dict["samples_count"]       =     eachuser["samples_count"]
        user_dict["credits_remaining"]       =     eachuser["credits_remaining"]
        user_dict["exported"]       =     eachuser["exported"]
        user_dict["storage_used"]       =     eachuser["storage_used"]
        user_dict["registration_date"]       =     eachuser["registration_date"]
        user_dict["registration_approval"]       =     eachuser["registration_approval"]
        user_dict["update_status"]       =     eachuser["update_status"]
        final_result.append(user_dict) 
    return jsonify(final_result)

#working
# function to fetch one user from the database , based on the user_id.
@app.route("/oneuser/<int:user_id>" , methods = ["GET"])
def oneuser(user_id):
    try:
        oneuser = None
        db = get_database()
        oneuser_cursor = db.execute("select * from users where user_id = ?", [user_id])
        oneuser = oneuser_cursor.fetchone()

        if oneuser is None:
            return jsonify({"error": "User not found"}), 404

        else:
            user_data = {
                            "user_id"               : oneuser["user_id"],
                            "full_name"             : oneuser["full_name"],
                            "username"              : oneuser["username"],
                            "password"              : oneuser["password"],
                            "password" : generate_password_hash(oneuser["password"], method="pbkdf2:sha256"),
                            "email"                 : oneuser["email"],
                            "phone"                 : oneuser["phone"],
                            "institution_organization": oneuser["institution_organization"],
                            "address"               : oneuser["address"],
                            "country"               : oneuser["country"],
                            "research_department"   : oneuser["research_department"],
                            "project_incharge_name" : oneuser["project_incharge_name"],
                            "project_count"         : oneuser["project_count"],
                            "samples_count"         : oneuser["samples_count"],
                            "credits_remaining"     : oneuser["credits_remaining"],
                            "exported"              : oneuser["exported"],
                            "storage_used"          : oneuser["storage_used"],
                            "registration_date"     : oneuser["registration_date"],
                            "registration_approval" : oneuser["registration_approval"],
                            "credits_requested"     : oneuser["credits_requested"],
                            "update_status"         : oneuser["update_status"],
                            }
            return jsonify(user_data)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500  # Internal Server Error
    

@app.route("/admindetails/<int:admin_id>" , methods = ["GET"])
def admindetails(admin_id):

    try:
        admin = None
        db = get_database()
        admin_cursor = db.execute("select * from admin where admin_id = ?", [admin_id])
        admin = admin_cursor.fetchone()

        if admin is None:
            return jsonify({"error": "Admin not found"}), 404

        else:
            admin_data = {
                            "admin_id"               : admin["admin_id"],
                            "full_name"             : admin["full_name"],
                            "username"              : admin["username"],
                            "password"              : admin["password"],
                            "email"                 : admin["email"],
                            "phone"                 : admin["phone"],
                            "address"               : admin["address"],
                            "country"               : admin["country"],
                            "role"                  : admin["role"]
                            }
            return jsonify(admin_data)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500  # Internal Server Error

@app.route("/approveuser/<int:user_id>" , methods = ["PUT"])
def approveuser(user_id):
    try:    
        db = get_database()
        db.execute("update users set registration_approval = true where user_id = ?", [user_id])
        db.commit()
        return jsonify({"message":"update Successfull"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500  # Internal Server Error

    


# function to delete the user based on the user_id.
@app.route("/deleteuser/<int:user_id>" , methods = ["DELETE"])
def deleteuser(user_id):
    db = get_database()
    db.execute("delete from users where user_id = ?" , [user_id])
    db.commit()
    return jsonify({"user - " : "user successfully deleted"})


@app.route("/updateprofile" , methods = ["POST"])
def updateprofile():
    new_user_data         = request.get_json()
    user_id               = new_user_data["user_id"]
    full_name             = new_user_data["full_name"]
    password              = new_user_data["password"]
    email                 = new_user_data["email"]
    phone                 = new_user_data["phone"]
    institution_organization= new_user_data["institution_organization"]
    address               = new_user_data["address"]
    country               = new_user_data["country"]
    research_department   = new_user_data["research_department"]
    project_incharge_name = new_user_data["project_incharge_name"]


    db = get_database()

    db.execute("update users set update_status = 'pending' WHERE user_id = ?", [user_id])

    user_cursor = db.execute("SELECT * FROM users_updates WHERE user_id = ?", [user_id])
    user = user_cursor.fetchone()

    if user:
        db.execute("update users_updates set full_name = ?,password = ? , email = ?, phone = ?, institution_organization = ?, address = ?, country = ?,research_department = ?, project_incharge_name = ?",[full_name, password , email, phone , institution_organization, address , country ,research_department , project_incharge_name,])
    else:
        db.execute("insert into users_updates (user_id,full_name,password , email, phone , institution_organization, address , country ,research_department , project_incharge_name) values (?,?, ?,? ,? ,? ,?, ?, ?, ?)",[user_id,full_name, password , email, phone , institution_organization, address , country ,research_department , project_incharge_name,])


    
    db.commit()
    return jsonify({"Message - " : "Prfile update initiation is successfull."})


@app.route("/updaterequesteduser/<int:user_id>" , methods = ["PUT"])
def updaterequesteduser(user_id):
    new_user_data         = request.get_json()
    full_name             = new_user_data["full_name"]
    email                 = new_user_data["email"]
    phone                 = new_user_data["phone"]
    institution_organization= new_user_data["institution_organization"]
    research_department   = new_user_data["research_department"]
    project_incharge_name = new_user_data["project_incharge_name"]
    address               = new_user_data["address"]
    country               = new_user_data["country"]
   


    db = get_database()

    db.execute("update users set full_name = ?, email = ?, phone = ?, institution_organization = ?, address = ?, country = ?,research_department = ?, project_incharge_name = ?, update_status = 'approved' where user_id = ?",[full_name,  email, phone , institution_organization, address , country ,research_department , project_incharge_name,user_id])

    db.execute("delete from users_updates where user_id = ?",[user_id])
    
    db.commit()
    return jsonify({"Message - " : "Prfile update successfull."})



@app.route("/showupdaterequestedusers" , methods = ["GET"])
def showupdaterequestedusers():
    allusers = None
    db = get_database()
    user_cursor = db.execute("select * from users_updates")
    allusers = user_cursor.fetchall()
    final_result = []
    for eachuser in allusers:
        user_dict = {}
        user_dict["user_id"]     =     eachuser["user_id"]
        user_dict["full_name"]   =     eachuser["full_name"]
        user_dict["password"]    =     eachuser["password"]
        user_dict["email"]       =     eachuser["email"]
        user_dict["phone"]       =     eachuser["phone"]
        user_dict["institution_organization"] =  eachuser["institution_organization"]
        user_dict["address"]       =     eachuser["address"]
        user_dict["country"]       =     eachuser["country"]
        user_dict["research_department"]       =     eachuser["research_department"]
        user_dict["project_incharge_name"]     =     eachuser["project_incharge_name"]
        final_result.append(user_dict) 
    return jsonify(final_result)

@app.route("/showupdaterequestedusersbyid/<int:user_id>" , methods = ["GET"])
def showupdaterequestedusersbyid(user_id):
    userdata = None
    db = get_database()
    user_cursor = db.execute("select * from users_updates where user_id = ?", [user_id])
    userdata = user_cursor.fetchone()
    user_dict = {
       "user_id"    :     userdata["user_id"],
       "full_name"  :     userdata["full_name"],
       "password"   :     userdata["password"],
       "email"      :     userdata["email"],
       "phone"      :     userdata["phone"],
       "institution_organization":  userdata["institution_organization"],
       "address"      :     userdata["address"],
       "country"      :     userdata["country"],
       "research_department"      :     userdata["research_department"],
       "project_incharge_name"    :     userdata["project_incharge_name"]
    }
    return jsonify(user_dict)

#working
# function to insert a new user into the api
@app.route("/buycredits/<int:user_id>" , methods = ["PUT"])
def buycredits(user_id):
    db = get_database()
    db.execute("update users set credits_requested = 1 where user_id = ?",[user_id])
    db.commit()
    return jsonify({"Message - " : "Request Sent Succesfully"})

# function to insert a new user into the api
@app.route("/addcredits/<int:user_id>" , methods = ["PUT"])
def addcredits(user_id):
    selectedCredits         = request.get_json()
    credits             = selectedCredits["credits"]
    db = get_database()
    db.execute("update users set credits_remaining = credits_remaining + ? where user_id = ?",[credits, user_id])
    db.execute("update users set credits_requested = 0 where user_id = ?",[user_id])
    db.commit()
    return jsonify({"Message - " : "Credits Added Succesfully"})

@app.route("/creditsrequestedusers" , methods = ["GET"])
def creditsrequestedusers():
    allusers = None
    db = get_database()
    user_cursor = db.execute("select * from users where credits_requested = 1")
    allusers = user_cursor.fetchall()
    final_result = []
    for eachuser in allusers:
        user_dict = {}
        user_dict["user_id"]     =     eachuser["user_id"]
        user_dict["full_name"]   =     eachuser["full_name"]
        user_dict["username"]    =     eachuser["username"]
        user_dict["password"]    =     eachuser["password"]
        user_dict["email"]       =     eachuser["email"]
        user_dict["phone"]       =     eachuser["phone"]
        user_dict["institution_organization"] =  eachuser["institution_organization"]
        user_dict["address"]       =     eachuser["address"]
        user_dict["country"]       =     eachuser["country"]
        user_dict["research_department"]       =     eachuser["research_department"]
        user_dict["project_incharge_name"]     =     eachuser["project_incharge_name"]
        user_dict["project_count"]       =     eachuser["project_count"]
        user_dict["samples_count"]       =     eachuser["samples_count"]
        user_dict["credits_remaining"]       =     eachuser["credits_remaining"]
        user_dict["exported"]       =     eachuser["exported"]
        user_dict["storage_used"]       =     eachuser["storage_used"]
        user_dict["registration_date"]       =     eachuser["registration_date"]
        user_dict["registration_approval"]       =     eachuser["registration_approval"]
        user_dict["update_status"]       =     eachuser["update_status"]
        final_result.append(user_dict) 
    return jsonify(final_result)

@app.route("/insertuser" , methods = ["POST"])
def insertuser():
    new_user_data         = request.get_json()
    full_name             = new_user_data["full_name"]
    username              = new_user_data["username"]
    password              = new_user_data["password"]
    email                 = new_user_data["email"]
    phone                 = new_user_data["phone"]
    institution_organization= new_user_data["institution_organization"]
    address               = new_user_data["address"]
    country               = new_user_data["country"]
    research_department   = new_user_data["research_department"]
    project_incharge_name = new_user_data["project_incharge_name"]
    project_count         = new_user_data["project_count"]
    samples_count         = new_user_data["samples_count"]
    credits_remaining     = new_user_data["credits_remaining"]
    exported              = new_user_data["exported"]
    storage_used          = new_user_data["storage_used"]
    registration_date     = new_user_data["registration_date"]
    registration_approval = new_user_data["registration_approval"]


    db = get_database()

    


    db.execute("insert into users (full_name, username,password , email, phone , institution_organization, address , country ,research_department , project_incharge_name,project_count, samples_count ,credits_remaining , exported, storage_used , registration_date, registration_approval) values (?,?, ?,? ,? ,? ,?, ?, ?, ?, ?, ? ,?, ?, ?,?,?)",[full_name, username,password , email, phone , institution_organization, address , country ,research_department , project_incharge_name,project_count, samples_count ,credits_remaining , exported, storage_used , registration_date, registration_approval])
    db.commit()
    return jsonify({"Message - " : "User successfully inserted."})


# function to register the user. 
# API endpoint for user registration
@app.route("/register", methods=["POST"])
def register_user():
    new_user_data = request.get_json()
    full_name = new_user_data["full_name"]
    username = new_user_data["username"]
    # Hash the password before storing it in the database
    password_hash = generate_password_hash(new_user_data["password"], method="pbkdf2:sha256")
    email = new_user_data["email"]
    phone = new_user_data["phone"]
    institution_organization = new_user_data["institution_organization"]
    address = new_user_data["address"]
    country = new_user_data["country"]
    research_department = new_user_data["research_department"]
    project_incharge_name = new_user_data["project_incharge_name"]
    

    try:
        db = get_database()
        db.execute("insert into users (full_name, username,password , email, phone , institution_organization, address , country ,research_department , project_incharge_name,project_count, samples_count ,credits_remaining , exported, storage_used ,  registration_approval) values (?,?, ?,? ,? ,? ,?, ?, ?, ?, ?, ? ,?, ?, ?,?)",
                   [full_name, username, password_hash, email, phone, institution_organization, address, country, research_department, project_incharge_name, 0, 0, 100, False, 0, False ])
        db.commit()
        return jsonify({"Message": "User registration successful"}), 201  # 201 Created status code

    except Exception as e:
        print(e)
        return jsonify({"Error": "Internal Server Error"}), 500  # 500 Internal Server Error status code

@app.route("/registeradmin", methods=["POST"])
def register_admin():
    new_user_data = request.get_json()
    full_name = new_user_data["full_name"]
    username = new_user_data["username"]
    # Hash the password before storing it in the database
    password_hash = generate_password_hash(new_user_data["password"], method="pbkdf2:sha256")
    email = new_user_data["email"]
    phone = new_user_data["phone"]
    address = new_user_data["address"]
    country = new_user_data["country"]
    role = new_user_data["role"]
    

    try:
        db = get_database()
        db.execute("INSERT INTO admin (full_name,username,password,email,phone,address,country,role) values (?,?, ?,? ,? ,? ,?, ?)",
                   [full_name, username, password_hash, email, phone,  address, country, role])
        db.commit()
        return jsonify({"Message": "Admin registration successful"}), 201  # 201 Created status code

    except Exception as e:
        print(e)
        return jsonify({"Error": "Internal Server Error"}), 500  # 500 Internal Server Error status code




# API endpoint for user login
@app.route("/login", methods=["POST"])
def login_user():
    login_data = request.get_json()
    email_or_username = login_data.get("email_or_username")
    password = login_data["password"]

    try:
        db = get_database()
        # Check if the input is an email or a username
        if "@" in email_or_username:
            user_cursor = db.execute("SELECT * FROM users WHERE email = ?", [email_or_username])
        else:
            user_cursor = db.execute("SELECT * FROM users WHERE username = ?", [email_or_username])

        user = user_cursor.fetchone()

        if user and check_password_hash(user["password"], password):
            # Authentication successful
            access_token = create_access_token(identity=user['username'])
            refresh_token = create_refresh_token(identity=user['username'])

            return jsonify({"Message": "Login successful", "accessToken": access_token,"refreshToken": refresh_token, 'userId': user['user_id'], 'approveduser': user['registration_approval']}), 200  # 200 OK status code
        else:
            # Authentication failed
            return jsonify({"Error": "Invalid email/username or password"}), 401  # 401 Unauthorized status code

    except Exception as e:
        print(e)
        return jsonify({"Error": "Internal Server Error"}), 500  # 500 Internal Server Error status code


@app.route("/adminlogin", methods=["POST"])
def login_admin():
    login_data = request.get_json()
    email_or_username = login_data.get("email_or_username")
    password = login_data["password"]

    try:
        db = get_database()
        # Check if the input is an email or a username
        if "@" in email_or_username:
            admin_cursor = db.execute("SELECT * FROM admin WHERE email = ?", [email_or_username])
        else:
            admin_cursor = db.execute("SELECT * FROM admin WHERE username = ?", [email_or_username])

        admin = admin_cursor.fetchone()

        if admin and check_password_hash(admin["password"], password):

            admin_data = {
                'username': admin['username'],
                'role': admin['role']
            }

            # Authentication successful
            access_token = create_access_token(identity=admin_data)
            refresh_token = create_refresh_token(identity=admin_data)

            return jsonify({"Message": "Login successful", "accessToken": access_token,"refreshToken": refresh_token, 'adminId': admin['admin_id'], "role":admin['role']}  ), 200  # 200 OK status code
        else:
            # Authentication failed
            return jsonify({"Error": "Invalid email/username or password"}), 401  # 401 Unauthorized status code

    except Exception as e:
        print(e)
        return jsonify({"Error": "Internal Server Error"}), 500  # 500 Internal Server Error status code



# Function to update the user based on user_id
@app.route("/updateuser/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    try:
        new_user_data = request.get_json()
        full_name = new_user_data["full_name"]
        password = new_user_data["password"]
        email = new_user_data["email"]
        phone = new_user_data["phone"]
        institution_organization = new_user_data["institution_organization"]
        address = new_user_data["address"]
        country = new_user_data["country"]
        research_department = new_user_data["research_department"]
        project_incharge_name = new_user_data["project_incharge_name"]

        db = get_database()

        print("password", password)

        if password:
            password_hash = generate_password_hash(new_user_data["password"], method="pbkdf2:sha256")
            db.execute("UPDATE users SET full_name = ?,  password = ?, email = ?, phone = ?, institution_organization = ?, address = ?, country = ?, research_department = ?, project_incharge_name = ? WHERE user_id = ?", [full_name, password_hash, email, phone, institution_organization, address, country, research_department, project_incharge_name, user_id])
        else:
            db.execute("UPDATE users SET full_name = ?, email = ?, phone = ?, institution_organization = ?, address = ?, country = ?, research_department = ?, project_incharge_name = ? WHERE user_id = ?", [full_name,  email, phone, institution_organization, address, country, research_department, project_incharge_name, user_id])

        db.commit()

        return jsonify({"Message": "User Details Successfully Updated."}), 200

    except sqlite3.Error as e:
        return {"error": f"SQLite error: {str(e)}"}, 500

    except Exception as e:
        return {"error": f"Internal Server Error: {str(e)}"}, 500

@app.route("/updateuserpassword/<int:user_id>", methods=["PUT"])
def updateuserpassword(user_id):
    try:
        new_user_data = request.get_json()
        password_hash = generate_password_hash(new_user_data["password"], method="pbkdf2:sha256")

        db = get_database()
        db.execute("UPDATE users SET password = ? where user_id = ?", [password_hash, user_id])
        db.commit()

        return jsonify({"Message": "User Password Successfully Updated."}), 200

    except sqlite3.Error as e:
        return {"error": f"SQLite error: {str(e)}"}, 500

    except Exception as e:
        return {"error": f"Internal Server Error: {str(e)}"}, 500

# showing all the contacts
@app.route("/showallcontacts", methods=["GET"])
def showallcontacts():
    try:
        allcontacts = None
        db = get_database()
        contact_cursor = db.execute("SELECT * FROM contacts")
        allcontacts = contact_cursor.fetchall()
        final_result = []
        for eachcontact in allcontacts:
            contact_dict = {
                "contact_id": eachcontact["contact_id"],
                "full_name" : eachcontact["full_name"],
                "username"  : eachcontact["username"],
                "email"     : eachcontact["email"],
                "phone"     : eachcontact["phone"],
                "institution_organization": eachcontact["institution_organization"],
                "address"   : eachcontact["address"],
                "country"   : eachcontact["country"],
            }
            final_result.append(contact_dict)
        return jsonify({"data": final_result}), 200  # Success: OK
    except Exception as e:
        return jsonify({"error": str(e)}), 500  # Internal Server Error


# showing onecontact based on the contact_id
@app.route("/onecontact/<int:contact_id>", methods=["GET"])
def onecontact(contact_id):
    try:
        onecontact = None
        db = get_database()
        onecontact_cursor = db.execute("SELECT * FROM contacts WHERE contact_id = ?", [contact_id])
        onecontact = onecontact_cursor.fetchone()

        if onecontact:
            result = {
                "contact_id": onecontact["contact_id"],
                "full_name": onecontact["full_name"],
                "username": onecontact["username"],
                "email": onecontact["email"],
                "phone": onecontact["phone"],
                "institution_organization": onecontact["institution_organization"],
                "address": onecontact["address"],
                "country": onecontact["country"]
            }
            return jsonify({"data": result}), 200  # Success: OK
        else:
            return jsonify({"error": "Contact not found"}), 404  # Not Found
    except Exception as e:
        return jsonify({"error": str(e)}), 500  # Internal Server Error



# function to delete the contact based on contact_id
@app.route("/deletecontact/<int:contact_id>", methods=["DELETE"])
def deletecontact(contact_id):
    try:
        db = get_database()
        db.execute("DELETE FROM contacts WHERE contact_id = ?", [contact_id])
        db.commit()
        return jsonify({"status": "success", "message": "Contact successfully deleted"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500



# Function to insert a new contact into the API
@app.route("/insertcontact", methods=["POST"])
def insertcontact():
    try:
        new_contact_data = request.get_json()
        full_name = new_contact_data["full_name"]
        username = new_contact_data["username"]
        email = new_contact_data["email"]
        phone = new_contact_data["phone"]
        institution_organization = new_contact_data["institution_organization"]
        address = new_contact_data["address"]
        country = new_contact_data["country"]
        
        db = get_database()
        db.execute("INSERT INTO contacts (full_name, username, email, phone, institution_organization, address, country) VALUES (?, ?, ?, ?, ?, ?, ?)", [full_name, username, email, phone, institution_organization, address, country])
        db.commit()
        return jsonify({"Message": "Contact successfully inserted."})
    except Exception as e:
        return handle_error(str(e), 500)


# Function to update the contact based on contact_id
@app.route("/updatecontact/<int:contact_id>", methods=["PUT"])
def updatecontact(contact_id):
    try:
        new_contact_data = request.get_json()
        full_name = new_contact_data["full_name"]
        username = new_contact_data["username"]
        email = new_contact_data["email"]
        phone = new_contact_data["phone"]
        institution_organization = new_contact_data["institution_organization"]
        address = new_contact_data["address"]
        country = new_contact_data["country"]
        
        db = get_database()
        db.execute("UPDATE contacts SET full_name = ?, username = ?, email = ?, phone = ?, institution_organization = ?, address = ?, country = ? WHERE contact_id = ?",
                   [full_name, username, email, phone, institution_organization, address, country, contact_id])
        db.commit()
        return jsonify({"Message": "Contact details successfully updated."})
    except Exception as e:
        return handle_error(str(e), 500)


# showing all the project details.
@app.route("/showallprojects", methods=["GET"])
def showallprojects():
    try:
        allprojects = None
        db = get_database()
        project_cursor = db.execute("SELECT * FROM projects")
        allprojects = project_cursor.fetchall()
        final_result = []
        for eachproject in allprojects:
            project_dict = {
                "project_id": eachproject["project_id"],
                "project_name": eachproject["project_name"],
                "number_of_cores": eachproject["number_of_cores"],
                "date": eachproject["date"],
                "confidence": eachproject["confidence"],
                "sample_size": eachproject["sample_size"],
                "folder_size": eachproject["folder_size"],
                "status": eachproject["status"],
                "user_id": eachproject["user_id"],
                "exported": eachproject["exported"],
            }
            final_result.append(project_dict)
        return jsonify(final_result)
    except Exception as e:
        return handle_error(str(e), 500)

@app.route("/showallprojects/<int:user_id>", methods=["GET"])
def showalluserprojects(user_id):
    try:
        allprojects = None
        db = get_database()
        project_cursor = db.execute("SELECT * FROM projects where user_id = ?", [user_id])
        allprojects = project_cursor.fetchall()
        final_result = []
        for eachproject in allprojects:
            project_dict = {
                "project_id": eachproject["project_id"],
                "project_name": eachproject["project_name"],
                "number_of_cores": eachproject["number_of_cores"],
                "date": eachproject["date"],
                "confidence": eachproject["confidence"],
                "sample_size": eachproject["sample_size"],
                "folder_size": eachproject["folder_size"],
                "status": eachproject["status"],
                "user_id": eachproject["user_id"],
                "exported": eachproject["exported"],
            }
            final_result.append(project_dict)
        return jsonify(final_result)
    except Exception as e:
        return handle_error(str(e), 500)


@app.route("/oneproject/<int:project_id>", methods=["GET"])
def oneproject(project_id):
    try:
        oneproject = None
        db = get_database()
        oneproject_cursor = db.execute("SELECT * FROM projects WHERE project_id = ?", [project_id])
        oneproject = oneproject_cursor.fetchone()
        if oneproject:
            return jsonify({"One Project Fetched": 
                            {
                                "project_id": oneproject["project_id"],
                                "project_name": oneproject["project_name"],
                                "number_of_cores": oneproject["number_of_cores"],
                                "date": oneproject["date"],
                                "confidence": oneproject["confidence"],
                                "sample_size": oneproject["sample_size"],
                                "folder_size": oneproject["folder_size"],
                                "status": oneproject["status"],
                                "user_id": oneproject["user_id"],
                                "exported": oneproject["exported"]
                            }
                        })
        else:
            return handle_error("Project not found", 404)
    except Exception as e:
        return handle_error(str(e), 500)


# Function to delete a project based on project_id
@app.route("/deleteproject/<int:project_id>", methods=["DELETE"])
def deleteproject(project_id):
    try:
        db = get_database()
        db.execute("DELETE FROM projects WHERE project_id = ?", [project_id])
        db.commit()
        return jsonify({"status": "success", "message": "Project successfully deleted"})
    except Exception as e:
        return handle_error(str(e), 500)


@app.route("/insertproject", methods=["POST"])
def insertproject():
    try:
        # with open('project_data.json') as json_file:
        #     data = json.load(json_file)

        # insert_query = '''
        #     INSERT INTO projects (project_name, date, confidence, sample_size, folder_size, status, user_id, exported) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    

        new_project_data = request.get_json()
        project_name = new_project_data["project_name"]
        # number_of_cores = new_project_data["number_of_cores"]
        date = new_project_data.get("date", datetime.datetime.now())
        confidence = new_project_data["confidence"]  
        sample_size = new_project_data["sample_size"]  
        folder_size = new_project_data["folder_size"]  
        status = new_project_data["status"]  
        user_id = new_project_data["user_id"]
        exported = new_project_data["exported"]  

        db = get_database()
        db.execute("INSERT INTO projects (project_name, date, confidence, sample_size, folder_size, status, user_id, exported) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   [project_name,  date, confidence, sample_size, folder_size, status, user_id, exported])


        # db.executemany(insert_query, [(item['project_name'], item['date'], item['confidence'],
        #                             item['sample_size'], item['folder_size'],
        #                             item['status'], item['user_id'], item['exported']) for item in data])
        db.commit()
        return jsonify({"status": "success", "message": "Project successfully inserted."})
    except Exception as e:
        return handle_error(str(e), 500)


# Function to update the project based on project_id
@app.route("/updateproject/<int:project_id>", methods=["PUT"])
def updateproject(project_id):
    try:
        new_project_data = request.get_json()
        project_name = new_project_data["project_name"]
        number_of_cores = new_project_data["number_of_cores"]  # Default value if not provided
        date = new_project_data.get("date", datetime.datetime.now())
        confidence = new_project_data["confidence"]  # You may adjust the default value
        sample_size = new_project_data["sample_size"]  # You may adjust the default value
        folder_size = new_project_data["folder_size"]  # You may adjust the default value
        status = new_project_data["status"]  # You may adjust the default value
        user_id = new_project_data["user_id"]
        exported = new_project_data["exported"]  # Default value if not provided

        db = get_database()
        db.execute("UPDATE projects SET project_name = ?, number_of_cores = ?, date = ?, confidence = ?, sample_size = ?, folder_size = ?, status = ?, user_id = ?, exported = ? WHERE project_id = ?",
                   [project_name, number_of_cores, date, confidence, sample_size, folder_size, status, user_id, exported, project_id])
        db.commit()
        return jsonify({"status": "success", "message": "Project details successfully updated."})
    except Exception as e:
        return handle_error(str(e), 500)


# getting all the samples information.
@app.route("/showallsamples", methods=["GET"])
def showallsamples():
    try:
        allsamples = None
        db = get_database()
        sample_cursor = db.execute("SELECT * FROM samples")
        allsamples = sample_cursor.fetchall()
        final_result = []
        for eachsample in allsamples:
            sample_dict = {
                "sample_id": eachsample["sample_id"],
                "sample_name": eachsample["sample_name"],
                "user_id": eachsample["user_id"],
                "project_id": eachsample["project_id"],
                "date": eachsample["date"],
                "file_size": eachsample["file_size"],
                "exported": eachsample["exported"],
            }
            final_result.append(sample_dict)
        return jsonify(final_result)
    except Exception as e:
        return handle_error(str(e), 500)


@app.route("/samplebyprojectid/<int:project_id>", methods=["GET"])
def samplebyprojectid(project_id):
    try:
        allsamples = None
        db = get_database()
        sample_cursor = db.execute("SELECT * FROM samples where project_id = ?", [project_id])
        allsamples = sample_cursor.fetchall()
        final_result = []
        for eachsample in allsamples:
            sample_dict = {
                "sample_id": eachsample["sample_id"],
                "sample_name": eachsample["sample_name"],
                "date": eachsample["date"],
                "file_size": eachsample["file_size"],
            }
            final_result.append(sample_dict)
        return jsonify(final_result)
    except Exception as e:
        return handle_error(str(e), 500)


# showing one sample based on sample_id
@app.route("/onesample/<int:sample_id>", methods=["GET"])
def onesample(sample_id):
    try:
        onesample = None
        db = get_database()
        onesample_cursor = db.execute("SELECT * FROM samples WHERE sample_id = ?", [sample_id])
        onesample = onesample_cursor.fetchone()
        if onesample:
            return jsonify({"One Sample Fetched": 
                            {
                                "sample_id": onesample["sample_id"],
                                "sample_name": onesample["sample_name"],
                                "user_id": onesample["user_id"],
                                "project_id": onesample["project_id"],
                                "date": onesample["date"],
                                "file_size": onesample["file_size"],
                                "exported": onesample["exported"]
                            }
                        })
        else:
            return handle_error("Sample not found", 404)
    except Exception as e:
        return handle_error(str(e), 500)


# Function to delete a sample based on sample_id
@app.route("/deletesample/<int:sample_id>", methods=["DELETE"])
def deletesample(sample_id):
    try:
        db = get_database()
        db.execute("DELETE FROM samples WHERE sample_id = ?", [sample_id])
        db.commit()
        return jsonify({"status": "success", "message": "Sample successfully deleted"})
    except Exception as e:
        return handle_error(str(e), 500)


# code to insert new sample into the api
@app.route("/insertsample", methods=["POST"])
def insertsample():
    try:
        # with open('sample_data.json') as json_file:
        #     data = json.load(json_file)

        # insert_query = '''
        #     INSERT INTO samples (sample_name, user_id, project_id, date, file_size, exported) VALUES (?, ?, ?, ?, ?, ?)'''
    


        new_sample_data = request.get_json()
        sample_name = new_sample_data["sample_name"]
        user_id = new_sample_data["user_id"]
        project_id = new_sample_data["project_id"]
        date = new_sample_data.get("date", datetime.datetime.now())
        file_size = new_sample_data["file_size"]
        exported = new_sample_data["exported"]
        db = get_database()
        db.execute("INSERT INTO samples (sample_name, user_id, project_id, date, file_size, exported) VALUES (?, ?, ?, ?, ?, ?)",
                   [sample_name, user_id, project_id, date, file_size, exported])
        # db.executemany(insert_query, [(item['sample_name'], item['user_id'], item['project_id'],
        #                             item['date'], item['file_size'], item['exported']) for item in data])
        db.commit()
        return jsonify({"status": "success", "message": "Sample successfully inserted."})
    except Exception as e:
        return handle_error(str(e), 500)


# function to update the sample size based on sample_id 
@app.route("/updatesample/<int:sample_id>", methods=["PUT"])
def updatesample(sample_id):
    try:
        new_sample_data = request.get_json()
        sample_name = new_sample_data["sample_name"]
        user_id = new_sample_data["user_id"]
        project_id = new_sample_data["project_id"]
        date = new_sample_data.get("date", datetime.datetime.now())
        file_size = new_sample_data.get("file_size", None)  # You may adjust the default value
        exported = new_sample_data.get("exported", False)  # Default value if not provided

        db = get_database()
        db.execute("UPDATE samples SET sample_name = ?, user_id = ?, project_id = ?, date = ?, file_size = ?, exported = ? WHERE sample_id = ?",
                   [sample_name, user_id, project_id, date, file_size, exported, sample_id])
        db.commit()
        return jsonify({"status": "success", "message": "Sample details successfully updated."})
    except Exception as e:
        return handle_error(str(e), 500)



# showing all the creadithistory
@app.route("/showallcredithistory", methods=["GET"])
def showallcredithistory():
    allcredithistory = None
    db = get_database()
    credithistory_cursor = db.execute("SELECT * FROM credit_history ORDER BY date desc")
    allcredithistory = credithistory_cursor.fetchall()
    final_result = []
    for eachcredithistory in allcredithistory:
        credithistory_dict = {
            "transaction_id": eachcredithistory["transaction_id"],
            "user_id": eachcredithistory["user_id"],
            "user_name": eachcredithistory["user_name"],
            "project_id": eachcredithistory["project_id"],
            "credits_used": eachcredithistory["credits_used"],
            "task": eachcredithistory["task"],
            "date": eachcredithistory["date"]
        }
        final_result.append(credithistory_dict)
    return jsonify(final_result)

@app.route("/usercredithistory/<int:user_id>", methods=["GET"])
def usercredithistory(user_id):
    usercredithistory = None
    db = get_database()
    usercredithistory_cursor = db.execute("SELECT * FROM credit_history WHERE user_id = ? ", [user_id])
    allusercredithistory = usercredithistory_cursor.fetchall()
    final_result = []
    for usercredithistory in allusercredithistory:
        credithistory_dict = {
            "transaction_id": usercredithistory["transaction_id"],
            "user_id": usercredithistory["user_id"],
            "username": usercredithistory["user_name"],
            "project_id": usercredithistory["project_id"],
            "credits_used": usercredithistory["credits_used"],
            "task": usercredithistory["task"],
            "date": usercredithistory["date"]
        }
        final_result.append(credithistory_dict)
    return jsonify(final_result)

# showing one creadit history based on user_id, and project_id
@app.route("/onecredithistory/<int:user_id>/<int:project_id>", methods=["GET"])
def onecredithistory(user_id, project_id):
    onecredithistory = None
    db = get_database()
    onecredithistory_cursor = db.execute("SELECT * FROM credit_history WHERE user_id = ? AND project_id = ?", [user_id, project_id])
    onecredithistory = onecredithistory_cursor.fetchone()

    return jsonify({"One Credit History Fetched": 
                    {
                        "user_id": onecredithistory["user_id"],
                        "project_id": onecredithistory["project_id"],
                        "credits_used": onecredithistory["credits_used"],
                        "task": onecredithistory["task"],
                        "date": onecredithistory["date"]
                    }
                })



# Function to delete credit history based on user_id and project_id
@app.route("/deletecredithistory/<int:user_id>/<int:project_id>", methods=["DELETE"])
def deletecredithistory(user_id, project_id):
    db = get_database()
    db.execute("DELETE FROM credit_history WHERE user_id = ? AND project_id = ?", [user_id, project_id])
    db.commit()
    return jsonify({"credit_history": "Credit history successfully deleted"})



# function to insert new credit history into the api / database table. 
@app.route("/insertcredithistory", methods=["POST"])
def insertcredithistory():
    new_credit_data = request.get_json()
    user_id = new_credit_data["user_id"]
    project_id = new_credit_data["project_id"]
    credits_used = new_credit_data["credits_used"]
    task = new_credit_data["task"]
    date = new_credit_data.get("date", datetime.datetime.now())
    db = get_database()
    db.execute("INSERT INTO credit_history (user_id, project_id, credits_used, task, date) VALUES (?, ?, ?, ?, ?)", [user_id, project_id, credits_used, task, date])

    db.commit()
    return jsonify({"Message": "Credit history entry successfully inserted."})



# Function to update credit history based on user_id and project_id
@app.route("/updatecredithistory/<int:user_id>/<int:project_id>", methods=["PUT"])
def updatecredithistory(user_id, project_id):
    new_credit_data = request.get_json()
    credits_used = new_credit_data["credits_used"]
    task = new_credit_data["task"]
    date = new_credit_data.get("date", datetime.datetime.now())
    db = get_database()
    db.execute("UPDATE credit_history SET credits_used = ?, task = ?, date = ? WHERE user_id = ? AND project_id = ?", [credits_used, task, date, user_id, project_id])
    db.commit()
    return jsonify({"Message": "Credit history details successfully updated."})



# showing all the faq.
@app.route("/showallfaq", methods=["GET"])
def showallfaq():
    allfaq = None
    db = get_database()
    faq_cursor = db.execute("SELECT * FROM faq")
    allfaq = faq_cursor.fetchall()
    final_result = []
    for eachfaq in allfaq:
        faq_dict = {
            "question_id": eachfaq["question_id"],
            "question": eachfaq["question"],
            "answer": eachfaq["answer"]
        }
        final_result.append(faq_dict)
    return jsonify(final_result)



# showing one faq based on question_id
@app.route("/onefaq/<int:question_id>", methods=["GET"])
def onefaq(question_id):
    onefaq = None
    db = get_database()
    onefaq_cursor = db.execute("SELECT * FROM faq WHERE question_id = ?", [question_id])
    onefaq = onefaq_cursor.fetchone()

    return jsonify({"One FAQ Fetched": 
                    {
                        "question_id": onefaq["question_id"],
                        "question": onefaq["question"],
                        "answer": onefaq["answer"]
                    }
                })



# inserting new faq into the api / database
@app.route("/insertfaq", methods=["POST"])
def insertfaq():
    new_faq_data = request.get_json()
    question = new_faq_data["question"]
    answer = new_faq_data["answer"]
    db = get_database()
    db.execute("INSERT INTO faq (question, answer) VALUES (?, ?)", [question, answer])
    db.commit()
    return jsonify({"Message": "FAQ entry successfully inserted."})



# Function to update FAQ based on question_id
@app.route("/updatefaq/<int:question_id>", methods=["PUT"])
def updatefaq(question_id):
    new_faq_data = request.get_json()
    question = new_faq_data["question"]
    answer = new_faq_data["answer"]
    db = get_database()
    db.execute("UPDATE faq SET question = ?, answer = ? where question_id = ?", [question, answer, question_id])
    db.commit()
    return jsonify({"Message": "FAQ details successfully updated."})



# Function to delete a FAQ based on question_id
@app.route("/deletefaq/<int:question_id>", methods=["DELETE"])
def deletefaq(question_id):
    db = get_database()
    db.execute("DELETE FROM faq WHERE question_id = ?", [question_id])
    db.commit()
    return jsonify({"Message": "FAQ successfully deleted"})



# showing all the contactus details. 
@app.route("/showallcontactus", methods=["GET"])
def showallcontactus():
    allcontactus = None
    db = get_database()
    contactus_cursor = db.execute("SELECT * FROM contact_us where status != 'resolved' ")
    allcontactus = contactus_cursor.fetchall()
    final_result = []
    for eachcontactus in allcontactus:
        contactus_dict = {
            "contact_id": eachcontactus["contact_id"],
            "user_id": eachcontactus["user_id"],
            "user_name": eachcontactus["user_name"],
            "subject": eachcontactus["subject"],
            "message": eachcontactus["message"],
            "status": eachcontactus["status"],
            "upload_screenshot": eachcontactus["upload_screenshot"],
            "contact_date" : eachcontactus["contact_date"]
        }
        final_result.append(contactus_dict)
    return jsonify(final_result)



# showing one contact details based one the user_id entered. 
@app.route("/onecontactus/<int:user_id>", methods=["GET"])
def onecontactus(user_id):
    onecontactus = None
    db = get_database()
    onecontactus_cursor = db.execute("SELECT * FROM contact_us WHERE user_id = ?", [user_id])
    onecontactus = onecontactus_cursor.fetchone()

    return jsonify({"One Contact Us Entry Fetched": 
                    {
                        "user_id": onecontactus["user_id"],
                        "user_name": onecontactus["user_name"],
                        "subject": onecontactus["subject"],
                        "message": onecontactus["message"],
                        "upload_screenshot": onecontactus["upload_screenshot"]
                    }
                })



# Function to delete a contact_us record based on user_id
@app.route("/deletecontactus/<int:user_id>", methods=["DELETE"])
def deletecontactus(user_id):
    db = get_database()
    db.execute("DELETE FROM contact_us WHERE user_id = ?", [user_id])
    db.commit()
    return jsonify({"contact_us": "Contact us record successfully deleted"})



# insert new contact us details into the api_database.
@app.route("/insertcontactus", methods=["POST"])
def insertcontactus():
    new_contactus_data = request.get_json()
    user_id = new_contactus_data["user_id"]
    user_name = new_contactus_data["user_name"]
    subject = new_contactus_data["subject"]
    message = new_contactus_data["message"]
    upload_screenshot = new_contactus_data.get("upload_screenshot")
    status = "uploaded"
    db = get_database()
    db.execute("INSERT INTO contact_us (user_id, user_name, subject, message, upload_screenshot, status) VALUES (?, ?, ?, ?, ?, ?)", [user_id, user_name, subject, message, upload_screenshot, status])
    db.commit()
    return jsonify({"Message": "Contact us entry successfully inserted."})



# Function to update contact_us based on user_id
@app.route("/updatecontactus/<int:contact_id>", methods=["PUT"])
def updatecontactus(contact_id):
    new_contactus_data = request.get_json() 
    status = new_contactus_data["status"]  
    db = get_database()
    db.execute("UPDATE contact_us SET  status = ? WHERE contact_id = ?", [status,  contact_id])
    db.commit()
    return jsonify({"Message": "Contact us details successfully updated."})



# showing all the processeddata 
@app.route("/showallprocesseddata", methods=["GET"])
def showallprocesseddata():
    allprocesseddata = None
    db = get_database()
    processeddata_cursor = db.execute("SELECT * FROM processed_data")
    allprocesseddata = processeddata_cursor.fetchall()
    final_result = []
    for eachprocesseddata in allprocesseddata:
        processeddata_dict = {
            "process_count": eachprocesseddata["process_count"],
            "date": eachprocesseddata["date"]
        }
        final_result.append(processeddata_dict)
    return jsonify({"data": final_result})



# showing one processeddata according the process_count
@app.route("/oneprocesseddata/<int:process_count>", methods=["GET"])
def oneprocesseddata(process_count):
    oneprocesseddata = None
    db = get_database()
    oneprocesseddata_cursor = db.execute("SELECT * FROM processed_data WHERE process_count = ?", [process_count])
    oneprocesseddata = oneprocesseddata_cursor.fetchone()

    return jsonify({"One Processed Data Entry Fetched": 
                    {
                        "process_count": oneprocesseddata["process_count"],
                        "date": oneprocesseddata["date"]
                    }
                })



# Function to delete processed_data based on process_count
@app.route("/deleteprocesseddata/<int:process_count>", methods=["DELETE"])
def deleteprocesseddata(process_count):
    db = get_database()
    db.execute("DELETE FROM processed_data WHERE process_count = ?", [process_count])
    db.commit()
    return jsonify({"processed_data": "Processed data record successfully deleted"})



# function to insert new processeddata into the api / database.
@app.route("/insertprocesseddata", methods=["POST"])
def insertprocesseddata():
    new_processed_data = request.get_json()
    process_count = new_processed_data["process_count"]
    date = new_processed_data.get("date", datetime.datetime.now())
    db = get_database()
    db.execute("INSERT INTO processed_data (process_count, date) VALUES (?, ?)", [process_count, date])
    db.commit()
    return jsonify({"Message": "Processed data entry successfully inserted."})



# Function to update processed_data based on process_count
@app.route("/updateprocesseddata/<int:process_count>", methods=["PUT"])
def updateprocesseddata(process_count):
    new_processed_data = request.get_json()
    # Assuming you have specific fields to update for processed_data
    # Adjust the fields accordingly

    # Sample fields (you can adjust them based on your actual schema)
    date = new_processed_data.get("date", datetime.datetime.now())

    db = get_database()
    db.execute("UPDATE processed_data SET date = ? WHERE process_count = ?",
               [date, process_count])
    db.commit()
    return jsonify({"Message": "Processed data details successfully updated."})




if __name__ == "__main__":
    app.run(debug = True)