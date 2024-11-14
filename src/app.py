from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_mysqldb import MySQL
from auth import validate_user, create_token, admin_required, send_email, log_activity, verify_token
from config import SECRET_KEY, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB

app = Flask(__name__)

# Configuración de CORS
origins = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:8000",
    "https://127.0.0.1:8000",
    "https://192.168.100.6:8000"
]
CORS(app, resources={r"/*": {"origins": origins}}, supports_credentials=True)

# Configuración de la base de datos
app.config['MYSQL_HOST'] = MYSQL_HOST
app.config['MYSQL_USER'] = MYSQL_USER
app.config['MYSQL_PASSWORD'] = MYSQL_PASSWORD
app.config['MYSQL_DB'] = MYSQL_DB
mysql = MySQL(app)

# Rutas de la aplicación
@app.route('/token', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    user = validate_user(username, password)
    if user:
        access_token = create_token({"sub": user[1], "role": user[8]})
        send_email(user[10], 'Tu Token de Autenticación', f'Tu token es: {access_token}')
        log_activity(user[0], 'login', 'Usuario inició sesión exitosamente.')
        return jsonify(access_token=access_token), 200

    return jsonify({"mensaje": "Credenciales inválidas"}), 401

@app.route('/verify-token', methods=['POST'])
def verify_user_token():
    token = request.json.get('token')
    role = verify_token(token)
    if role:
        return jsonify({"role": role}), 200
    return jsonify({"mensaje": "Token inválido"}), 401

@app.route('/users/me', methods=['GET'])
@admin_required
def read_users_me():
    token = request.headers.get('Authorization').split(" ")[1]
    user_data = verify_token(token)

    if user_data:
        return jsonify({
            "id": user_data[0],
            "username": user_data[1],
            "name": user_data[2],
            "role": user_data[8]
        })
    return jsonify({'mensaje': 'Credenciales inválidas'}), 401

@app.route('/dashboard', methods=['GET'])
@admin_required
def dashboard():
    token = request.headers.get('Authorization').split(" ")[1]
    user_data = verify_token(token)

    if user_data:
        role = user_data[7]
        username = user_data[1]
        if role == 'admin':
            return {"message": f"Welcome to the admin dashboard, {username}!"}
        elif role == 'support':
            return {"message": f"Welcome to the support dashboard, {username}!"}
        elif role == 'client':
            return {"message": f"Welcome to the client dashboard, {username}!"}
        
        return jsonify({'mensaje': 'Acceso prohibido: permisos insuficientes.'}), 403
    
    return jsonify({'mensaje': 'Credenciales inválidas'}), 401

if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.load_cert_chain('C:/xampp/apache/conf/ssl.crt/server.crt',
                            'C:/xampp/apache/conf/ssl.key/server.key')
    app.run(host='0.0.0.0', port=8000, ssl_context=context)
