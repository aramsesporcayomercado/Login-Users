from flask import Flask, jsonify, request
from flask_mysqldb import MySQL
from jose import jwt, JWTError
from datetime import datetime, timedelta
from passlib.context import CryptContext
from functools import wraps
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB
from flask_cors import CORS
from asgiref.wsgi import WsgiToAsgi

app = Flask(__name__)
CORS(app)  # Habilitar CORS si es necesario
# Configurar CORS
origins = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:8000",
    "https://127.0.0.1:8000",
    "https://192.168.100.6:8000"
    
    # Añade aquí otros orígenes permitidos si es necesario
]

CORS(app, resources={r"/*": {"origins": origins}}, supports_credentials=True)


# Configuración de la base de datos desde config.py
app.config['MYSQL_HOST'] = MYSQL_HOST
app.config['MYSQL_USER'] = MYSQL_USER
app.config['MYSQL_PASSWORD'] = MYSQL_PASSWORD
app.config['MYSQL_DB'] = MYSQL_DB

# Configurar SSL
app.config['MYSQL_SSL_CA'] = 'C:/certificados/ca-cert.pem'  # Ruta al certificado CA
app.config['MYSQL_SSL_CERT'] = 'C:/xampp/apache/conf/ssl.crt/server.crt'  # Ruta al certificado del servidor
app.config['MYSQL_SSL_KEY'] = 'C:/xampp/apache/conf/ssl.key/server.key'  # Ruta a la clave privada del servidor


mysql = MySQL(app)

# Configuraciones para el manejo de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def validate_user(username, password):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()  # Obtiene el primer resultado

    # Verifica si el usuario existe
    if user is None:
        print(f"Usuario '{username}' no encontrado.")
        return None  # El usuario no existe
    # Verifica si la contraseña es correcta
    if password is None:
        print("La contraseña es None.")
        return None  # La contraseña no puede ser None

    if pwd_context.verify(password, user[9]):  # Suponiendo que el hash está en la columna 9
        return user

    print("Contraseña incorrecta.")
    return None  # La contraseña es incorrecta

def create_token(data):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'mensaje': 'Token es requerido.'}), 401
        
        try:
            payload = jwt.decode(token.split(" ")[1], SECRET_KEY, algorithms=[ALGORITHM])
            role = payload.get('role')
            if role != 'admin':
                return jsonify({'mensaje': 'Acceso denegado.'}), 403
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({'mensaje': 'Token inválido.'}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

@app.route('/token', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    user = validate_user(username, password)
    if user:
        access_token = create_token({"sub": user[1], "role": user[8]})  # Suponiendo que el rol está en la columna 7
        return jsonify(access_token=access_token), 200
    
    return jsonify({"mensaje": "Credenciales inválidas"}), 401

@app.route('/verify-token', methods=['POST'])
def verify_token():
    token = request.json.get('token')
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if username is None:
            return jsonify({'mensaje': 'Token inválido'}), 401
        
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        
        if user_data is None:
            return jsonify({'mensaje': 'Token inválido'}), 401

        return {"role": user_data[8]}  # Devuelve el rol del usuario
    
    except jwt.JWTError:
        return jsonify({'mensaje': 'Token inválido'}), 401

@app.route('/users/me', methods=['GET'])
@admin_required
def read_users_me():
    token = request.headers.get('Authorization').split(" ")[1]
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()

        if user_data is None:
            return jsonify({'mensaje': 'Credenciales inválidas'}), 401
        
        return jsonify({
            "id": user_data[0],
            "username": user_data[1],
            "name": user_data[2],
            "role": user_data[8]
        })
    
    except jwt.JWTError:
        return jsonify({'mensaje': 'Credenciales inválidas'}), 401

@app.route('/dashboard', methods=['GET'])
@admin_required
def dashboard():
    token = request.headers.get('Authorization').split(" ")[1]
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()

        if user_data is None:
            return jsonify({'mensaje': 'Credenciales inválidas'}), 401

        role = user_data[7]  # Suponiendo que el rol está en la columna 7
        
        if role == 'admin':
            return {"message": f"Welcome to the admin dashboard, {username}!"}
        elif role == 'support':
            return {"message": f"Welcome to the support dashboard, {username}!"}
        elif role == 'client':
            return {"message": f"Welcome to the client dashboard, {username}!"}
        
        return jsonify({'mensaje': 'Acceso prohibido: permisos insuficientes.'}), 403
    
    except jwt.JWTError:
        return jsonify({'mensaje': 'Credenciales inválidas'}), 401

# # Convertimos la aplicación Flask a ASGI
# asgi_app = WsgiToAsgi(app)

if __name__ == '__main__':
    # import uvicorn
    # uvicorn.run(asgi_app, host="0.0.0.0", port=8000)
    app.run(
        host='0.0.0.0',
        port=8000,
        ssl_context=(
            r'C:/xampp/apache/conf/ssl.crt/server.crt',  # Ruta al certificado del servidor
            r'C:/xampp/apache/conf/ssl.key/server.key'    # Ruta a la clave privada del servidor
        )
    )