import base64
from flask import jsonify, request
from flask_mysqldb import MySQL
from jose import jwt, JWTError
from datetime import datetime, timedelta
from passlib.context import CryptContext
from functools import wraps
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from email.mime.text import MIMEText
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, SCOPES

# Inicialización de conexión MySQL
mysql = MySQL()

# Configuración de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_cursor():
    """Obtiene un cursor para interactuar con la base de datos."""
    return mysql.connection.cursor()

def validate_user(username, password):
    cursor = get_cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user is None:
            print(f"Usuario '{username}' no encontrado.")
            return None

        if not password or not pwd_context.verify(password, user[9]):
            print("Contraseña incorrecta.")
            return None

        return user
    finally:
        cursor.close()

def create_token(data):
    """Genera un token JWT para el usuario."""
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def admin_required(f):
    """Decorador para verificar rol de administrador."""
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
    try:
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    except Exception as e:
        print("Error al cargar las credenciales:", e)

    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(
            'client_secret.json', SCOPES)
        creds = flow.run_local_server(port=0)

    service = build('gmail', 'v1', credentials=creds)

    email_message = create_email(subject, message_text, to_email)
    try:
        service.users().messages().send(userId='me', body=email_message).execute()
        print("Correo enviado con éxito.")
    except Exception as error:
        print(f"Error al enviar el correo: {error}")

def log_activity(user_id, action, description):
    """Registra la actividad del usuario."""
    cursor = get_cursor()
    try:
        cursor.execute("INSERT INTO activity_log (user_id, action, description) VALUES (%s, %s, %s)", 
                       (user_id, action, description))
        mysql.connection.commit()
    finally:
        cursor.close()

def verify_token(token):
    """Verifica el token y obtiene el rol del usuario."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        
        if username is None:
            return None
        
        cursor = get_cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        return user_data[8] if user_data else None
    except JWTError:
        return None
