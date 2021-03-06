from flask import *
import ssl
import mysql.connector

app = Flask(__name__)

context = ssl.SSLContext()
context.load_cert_chain('ssl/server.crt', 'ssl/server.key')

def getMysqlConnection():
    config = {
            'host': 'Digital-Signature-API-MySQL',
            'user': 'root',
            'password': '123',
            'database': 'Digital-Signature-API',
            'auth_plugin':'mysql_native_password'
        }
    connection = mysql.connector.connect(**config)
    return connection

def create_tables():
    db = getMysqlConnection()
    cursor = db.cursor(prepared=True)
    sql = 'CREATE TABLE IF NOT EXISTS users (id INT(255) UNSIGNED AUTO_INCREMENT PRIMARY KEY, username VARCHAR(256) NOT NULL, password VARCHAR(256) NOT NULL, certificate TEXT, reg_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)'
    cursor.execute(sql)
    db.commit()
    sql = 'CREATE TABLE IF NOT EXISTS files (FID INT(255) UNSIGNED AUTO_INCREMENT PRIMARY KEY, filename VARCHAR(30) NOT NULL, content LONGBLOB NOT NULL, signature TINYBLOB NOT NULL, source TEXT NOT NULL, destination TEXT NOT NULL, reg_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)'
    cursor.execute(sql)
    db.commit()
    cursor.close()
    db.close()

create_tables()

@app.route('/get_certificates', methods=['GET'])
def get_certificates():
    db = getMysqlConnection()
    cursor = db.cursor(prepared=True)
    sql = 'SELECT username, certificate FROM users'
    cursor.execute(sql)
    data = cursor.fetchall()
    jsondata = {}
    for i in data:
        jsondata[i[0]] = (i[1])
    cursor.close()
    db.close()
    return jsondata

@app.route('/login', methods=['POST'])
def login():
    status_code = "FAIL"
    description = "Login Failed"
    try:
        username = str(request.form['username'])
        password = str(request.form['password'])
        certificate = str(request.form['certificate'])
    except:
        response = {
        "statusCode":status_code,
        "description":description
        }
        return response
    db = getMysqlConnection()
    cursor = db.cursor(prepared=True)
    sql = 'SELECT * FROM users WHERE username = %s and password = %s'
    cursor.execute(sql, (username, password))
    result = cursor.fetchone()
    rc = cursor.rowcount
    if rc > 0 :
        status_code = "OK"
        if result[3] == None:
            description = "New User"
            sql = 'UPDATE users SET certificate = %s WHERE username = %s and password = %s'
            cursor.execute(sql, (certificate, username, password))
            db.commit()
        elif result[3] != certificate:
            description = "Invalid Certificate"
        else:
            description = "Old User"

    cursor.close()
    db.close()
    response = {
    "statusCode":status_code,
    "description":description
    }
    return response

@app.route('/update_cert', methods=['POST'])
def update_cert():
    status_code = "FAIL"
    description = "Not Updated"
    try:
        username = str(request.form['username'])
        password = str(request.form['password'])
        certificate = str(request.form['certificate'])
    except:
        response = {
        "statusCode":status_code,
        "description":description
        }
        return response
    db = getMysqlConnection()
    cursor = db.cursor(prepared=True)
    sql = 'SELECT * FROM users WHERE username = %s and password = %s'
    cursor.execute(sql, (username, password))
    result = cursor.fetchone()
    rc = cursor.rowcount
    if rc > 0 :
        status_code = "OK"
        if result[3] != None:
            description = "Updated"
            sql = 'UPDATE users SET certificate = %s WHERE username = %s and password = %s'
            cursor.execute(sql, (certificate, username, password))
            db.commit()
    cursor.close()
    db.close()
    response = {
    "statusCode":status_code,
    "description":description
    }
    return response

@app.route('/upload_file', methods=['POST'])
def upload_file():
    status_code = "FAIL"
    description = "Server Error"
    try:
        username = str(request.form['username'])
        password = str(request.form['password'])
        filename = request.files['content'].filename
        content = request.files['content'].read()
        signature = request.files['signature'].read()
        destination = str(request.form['destination'])
    except:
        response = {
        "statusCode":status_code,
        "description":description
        }
        return response
    if destination == username:
        description = "Invalid Destination"
        response = {
        "statusCode":status_code,
        "description":description
        }
        return response
    else:
        db = getMysqlConnection()
        cursor = db.cursor(prepared=True)
        sql = 'SELECT * FROM users WHERE username = %s and password = %s'
        cursor.execute(sql, (username, password))
        result = cursor.fetchone()
        rc = cursor.rowcount
        if rc > 0 :
            status_code = "OK"
            # Check whether destination is valid
            sql = 'SELECT * FROM users WHERE username = %s'
            cursor.execute(sql, (destination,))
            result = cursor.fetchone()
            rc = cursor.rowcount
            if rc > 0:
                description = "Uploaded"
                sql = 'INSERT INTO files(filename, content, signature, source, destination) VALUES (%s, %s, %s, %s, %s)'
                cursor.execute(sql, (filename, content, signature, username, destination))
                db.commit()
            else:
                description = "Invalid Destination"
        cursor.close()
        db.close()
        response = {
        "statusCode":status_code,
        "description":description
        }
    return response

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5678, ssl_context=context)