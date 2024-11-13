from flask import Flask, jsonify, request, Blueprint
from flask_mysqldb import MySQL
from auth.activity_log import log_activity  # Asegúrate de que esta función esté disponible
from functools import wraps
from config import SECRET_KEY, ALGORITHM
from jose import jwt, JWTError


# Definición del Blueprint
users_bp = Blueprint('users', __name__)
mysql = MySQL()

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

def validar_datos_usuario(data):
    required_fields = ['username', 'name', 'paternal', 'maternal', 'ciudad', 'pais', 'company', 'role', 'hashed_password', 'email', 'date', 'disabled']
    for field in required_fields:
        if field not in data or data[field] is None or str(data[field]).strip() == "":
            return False, f"El campo '{field}' es obligatorio y no puede estar vacío."
    return True, ""

@users_bp.route('/users', methods=['GET'])
@admin_required
def listar_usuarios():
    try:
        cursor = mysql.connection.cursor()
        sql = """SELECT id, username, name, paternal, maternal, ciudad, pais, company, role, hashed_password, email, date, disabled FROM users"""
        cursor.execute(sql)
        datos = cursor.fetchall()
        usuarios = []
        for fila in datos:
            usuario = {
                'id': fila[0],
                'username': fila[1],
                'name': fila[2],
                'paternal': fila[3],
                'maternal': fila[4],
                'ciudad': fila[5],
                'pais': fila[6],
                'company': fila[7],
                'role': fila[8],
                'hashed_password': fila[9],
                'email': fila[10],
                'date': fila[11],
                'disabled': fila[12]
            }
            usuarios.append(usuario)
        return jsonify({'usuarios': usuarios, 'mensaje': "Usuarios listados."})
    except Exception as ex:
        return jsonify({'mensaje': f"Error al listar usuarios: {str(ex)}"}), 500

@users_bp.route('/users/<id>', methods=['GET'])
@admin_required
def leer_usuario(id):
    try:
        cursor = mysql.connection.cursor()
        sql = """SELECT id, username, name, paternal, maternal, ciudad, pais, company, role, hashed_password, email, date, disabled FROM users WHERE id = %s"""
        cursor.execute(sql, (id,))
        datos = cursor.fetchone()
        if datos:
            usuario = {
                'id': datos[0],
                'username': datos[1],
                'name': datos[2],
                'paternal': datos[3],
                'maternal': datos[4],
                'ciudad': datos[5],
                'pais': datos[6],
                'company': datos[7],
                'role': datos[8],
                'hashed_password': datos[9],
                'email': datos[10],
                'date': datos[11],
                'disabled': datos[12]
            }
            return jsonify({'usuario': usuario, 'mensaje': "Usuario encontrado."})
        else:
            return jsonify({'mensaje': "Usuario no encontrado."}), 404
    except Exception as ex:
        return jsonify({'mensaje': f"Error al leer usuario: {str(ex)}"}), 500

@users_bp.route('/users', methods=['POST'])
@admin_required
def registrar_usuario():
    try:
        validacion_exitosa, mensaje_error = validar_datos_usuario(request.json)
        if not validacion_exitosa:
            return jsonify({'mensaje': mensaje_error}), 400
        
        cursor = mysql.connection.cursor()
        sql = """INSERT INTO users (id , username , name , paternal , maternal , ciudad , pais , company , role , hashed_password , email , date , disabled) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
        
        cursor.execute(sql,
                       (request.json['id'], request.json['username'], request.json['name'],
                        request.json['paternal'], request.json['maternal'], request.json['ciudad'],
                        request.json['pais'], request.json['company'], request.json['role'],
                        request.json['hashed_password'], request.json['email'], request.json['date'],
                        request.json['disabled']))
        
        mysql.connection.commit()
        
        # Registrar la actividad de creación de usuario.
        log_activity(request.json['id'], "create_user", f"Usuario {request.json['username']} registrado.")
        
        return jsonify({'mensaje': "Usuario registrado"}), 201
    except Exception as ex:
        return jsonify({'mensaje': f"Error al registrar usuario: {str(ex)}"}), 500

@users_bp.route('/users/<id>', methods=['DELETE'])
@admin_required
def eliminar_usuario(id):
    try:
        cursor = mysql.connection.cursor()
        
        # Verificar si el usuario existe antes de eliminar
        sql_check = "SELECT * FROM users WHERE id = %s"
        cursor.execute(sql_check, (id,))
        
        if not cursor.fetchone():
            return jsonify({'mensaje': "Usuario no encontrado."}), 404
        
        sql_delete = "DELETE FROM users WHERE id = %s"
        cursor.execute(sql_delete, (id,))
        
        mysql.connection.commit()
        
        # Registrar la actividad de eliminación de usuario.
        log_activity(id,"delete_user",f"Usuario con ID {id} eliminado.")
        
        return jsonify({'mensaje': "Usuario eliminado."})
    except Exception as ex:
        return jsonify({'mensaje': f"Error al eliminar usuario: {str(ex)}"}), 500

@users_bp.route('/users/<id>', methods=['PUT'])
@admin_required
def modificar_usuario(id):
    try:
        validacion_exitosa, mensaje_error = validar_datos_usuario(request.json)
        
        if not validacion_exitosa:
            return jsonify({'mensaje': mensaje_error}), 400
        
        cursor = mysql.connection.cursor()
        
        # Verificar si el usuario existe antes de modificar.
        sql_check="SELECT * FROM users WHERE id=%s"
        cursor.execute(sql_check,(id,))
        
        if not cursor.fetchone():
            return jsonify({'mensaje' : "Usuario no encontrado."}),404
        
        sql_update="""UPDATE users SET username=%s,name=%s,paternal=%s,maternal=%s,
                      ciudad=%s,pais=%s, company=%s,
                      role=%s, hashed_password=%s,
                      email=%s,
                      date=%s,
                      disabled=%s WHERE id=%s"""
        
        cursor.execute(sql_update,
                       (request.json['username'], request.json['name'],
                        request.json['paternal'], request.json['maternal'],
                        request.json['ciudad'], request.json['pais'],
                        request.json['company'], request.json['role'],
                        request.json['hashed_password'], request.json['email'],
                        request.json['date'], request.json['disabled'], id))
        
        mysql.connection.commit()
        # Registrar la actividad de creación de usuario.
        log_activity(id,"update_user",f"Usuario con ID {id} actualizado.")
        return jsonify({'mensaje':'Usuario actualizado.'})
    except Exception as ex:
         return jsonify({'mensaje' : f'Error al actualizar usuario: {str(ex)}'}),500

# Crear la aplicación principal y registrar el Blueprint
app = Flask(__name__)
app.register_blueprint(users_bp)

if __name__ == '__main__':
    app.run(debug=True)