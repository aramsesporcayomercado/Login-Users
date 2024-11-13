import base64
from flask import Flask, jsonify, request
from flask_mysqldb import MySQL
from jose import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from functools import wraps
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from email.mime.text import MIMEText
from auth.activity_log import log_activity

# Inicializar la aplicación y la conexión a MySQL
app = Flask(__name__)

# Configuración de la base de datos desde config.py
app.config['MYSQL_HOST'] = MYSQL_HOST
app.config['MYSQL_USER'] = MYSQL_USER
app.config['MYSQL_PASSWORD'] = MYSQL_PASSWORD
app.config['MYSQL_DB'] = MYSQL_DB

mysql = MySQL(app)

# Configuraciones para el manejo de contraseñas y JWT
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def get_cursor():
    """Obtiene un cursor para interactuar con la base de datos."""
    return mysql.connection.cursor()

def create_email(subject, message_text, to):
    """Crea un mensaje en formato MIME."""
    message = MIMEText(message_text)
    message['to'] = to
    message['subject'] = subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {'raw': raw_message}

def send_email(to_email, subject, message_text):
    """Envía un correo electrónico usando la API de Gmail."""
    creds = None

    # Cargar credenciales desde el archivo token.json (si existen)
    try:
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    except Exception as e:
        print("Error al cargar las credenciales:", e)

    # Si no hay credenciales válidas, solicita al usuario que inicie sesión
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(
            'client_secret_711184362793-1m9afh2ag51rosfopjda4lmal5sos91u.apps.googleusercontent.com.json', SCOPES)
        creds = flow.run_local_server(port=0)

    service = build('gmail', 'v1', credentials=creds)

    email_message = create_email(subject, message_text, to_email)
    
    try:
        service.users().messages().send(userId='me', body=email_message).execute()
        print("Correo enviado con éxito.")
    except Exception as error:
        print(f"Error al enviar el correo: {error}")

def validate_user(username, password):
    cursor = get_cursor()  # Obtiene un nuevo cursor

    try:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()  # Obtiene el primer resultado

        # Verifica si el usuario existe
        if user is None:
            print(f"Usuario '{username}' no encontrado.")
            return None  # El usuario no existe
        
        # Verifica si la contraseña es válida
        if not password:  # Verifica si la contraseña está vacía
            print("La contraseña está vacía.")
            return None  # La contraseña no puede estar vacía

        if pwd_context.verify(password, user[9]):  # Asegúrate de que este índice sea correcto
            return user

        print("Contraseña incorrecta.")
        return None  # La contraseña es incorrecta

    finally:
        cursor.close()  # Cierra el cursor al final

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
        access_token = create_token({"sub": user[1], "role": user[8]})  # Suponiendo que el rol está en la columna 8
        send_email(user[10], 'Tu Token de Autenticación', f'Tu token es: {access_token}')  # Suponiendo que el email está en la columna 10
        log_activity(user[0], 'login', 'Usuario inició sesión exitosamente.')  # user[0] es el ID del usuario
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
        
        cursor = get_cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        
        if user_data is None:
            return jsonify({'mensaje': 'Token inválido'}), 401

        return {"role": user_data[8]}  # Devuelve el rol del usuario
    
    except jwt.JWTError:
        return jsonify({'mensaje': 'Token inválido'}), 401
