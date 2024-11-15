from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import os
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Necesario para flash y session
DATA_FILE = 'data.json'
login_attempts = {}  # Para rastrear intentos fallidos de inicio de sesión

# Funciones de persistencia
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
    else:
        data = {"users": [], "products": []}
        save_data(data)
    if "users" not in data:
        data["users"] = []
    if "products" not in data:
        data["products"] = []
    return data


def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)
        print(f"Datos guardados en {DATA_FILE}: {data}")  # Verifica que se guarda correctamente



# Función para obtener productos
def get_products():
    data = load_data()  # Cargar los datos desde el archivo
    return data["products"]  # Devolver la lista de productos


# Validación del correo electrónico
def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

# Verificación de complejidad de contraseñas
def is_valid_password(password):
    return (len(password) >= 8 and any(c.isupper() for c in password)
            and any(c.islower() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()_-+=" for c in password))

# CRUD de usuario
def create_user(username, password, full_name, email, phone, role="user"):
    data = load_data()
    if any(user["username"] == username for user in data["users"]):
        return False
    hashed_password = generate_password_hash(password)
    data["users"].append({
        "username": username,
        "password": hashed_password,
        "full_name": full_name,
        "email": email,
        "phone": phone,
        "role": role
    })
    save_data(data)
    return True


def read_user(username):
    data = load_data()
    return next((user for user in data["users"] if user["username"] == username), None)


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = read_user(username)

    # Verificar si el usuario está bloqueado
    if username in login_attempts:
        attempts, lock_until = login_attempts[username]
        if datetime.now() < lock_until:
            flash('Usuario bloqueado temporalmente. Intente más tarde.', 'danger')
            return redirect(url_for('index'))

    if user:
        print(f"Contraseña almacenada (hashed): {user['password']}")
        print(f"Contraseña ingresada: {password}")
        if check_password_hash(user['password'], password):
            session['username'] = username
            session['role'] = user.get("role", "user")  # Asegúrate de que la sesión esté configurada correctamente
            login_attempts.pop(username, None)  # Reiniciar intentos fallidos
            flash('Inicio de sesión exitoso!', 'success')
            return redirect(url_for('dashboard'))

    flash('Credenciales incorrectas', 'danger')
    return redirect(url_for('index'))


# Cierre automático de sesión por inactividad
@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)  # El tiempo de vida de la sesión se puede ajustar aquí

# Ruta de inicio (login)
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))  # Si ya está autenticado, redirigir al dashboard
    return render_template('login.html')  # Si no, mostrar el formulario de login


@app.route('/register')
def register_page():
    if 'username' in session:
        return redirect(url_for('dashboard'))  # Redirigir al dashboard si ya está autenticado
    return render_template('register.html')

# Ruta para procesar el registro de usuario
@app.route('/register', methods=['POST'])
def register():
    full_name = request.form['full_name']
    username = request.form['username']
    email = request.form['email']
    phone = request.form['phone']
    password = request.form['password']

    if not is_valid_email(email):
        flash('Formato de correo electrónico inválido.', 'danger')
        return redirect(url_for('register_page'))
    if not is_valid_password(password):
        flash('La contraseña no cumple con los requisitos de complejidad.', 'danger')
        return redirect(url_for('register_page'))

    if create_user(username, password, full_name, email, phone):
        flash('Usuario creado exitosamente!', 'success')
        return redirect(url_for('index'))
    else:
        flash('El usuario ya existe.', 'danger')
        return redirect(url_for('register_page'))


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Verificar si las contraseñas coinciden
        if new_password != confirm_password:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('reset_password'))

        # Verificar si el usuario existe
        user = read_user(username)
        if not user:
            flash('El usuario no existe.', 'danger')
            return redirect(url_for('reset_password'))

        # Imprimir la contraseña actual antes del cambio
        print(f"Contraseña actual (hashed) para {username}: {user['password']}")

        # Actualizar la contraseña
        hashed_password = generate_password_hash(new_password)
        user['password'] = hashed_password

        # Imprimir la nueva contraseña después del cambio
        print(f"Nueva contraseña (hashed) para {username}: {hashed_password}")

        # Cargar los datos actuales y actualizar el usuario en la lista
        data = load_data()
        for i, existing_user in enumerate(data['users']):
            if existing_user['username'] == username:
                data['users'][i] = user
                break

        # Guardar los datos con la nueva contraseña
        save_data(data)

        flash('Contraseña restablecida exitosamente!', 'success')
        return redirect(url_for('index'))

    return render_template('reset_password.html')


@app.route('/add_product', methods=['POST'])
def add_product_route():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Acceso denegado: solo los administradores pueden agregar productos.', 'danger')
        return redirect(url_for('index'))

    name = request.form['name']
    price = float(request.form['price'])
    quantity = int(request.form['quantity'])
    add_product(name, price, quantity)  # Llamamos a la función add_product
    flash('Producto agregado exitosamente!', 'success')
    return redirect(url_for('dashboard'))

def add_product(name, price, quantity):
    data = load_data()
    product = {
        "id": len(data["products"]) + 1,
        "name": name,
        "price": price,
        "quantity": quantity
    }
    data["products"].append(product)
    save_data(data)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product_route(product_id):
    data = load_data()
    data['products'] = [product for product in data['products'] if product['id'] != product_id]
    save_data(data)
    flash('Producto eliminado exitosamente!', 'success')
    return redirect(url_for('dashboard'))



@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))  # Redirigir si no está autenticado

    # Permitir que tanto los administradores como los usuarios comunes vean el dashboard
    if session.get('role') not in ['admin', 'user']:  # Solo los usuarios o administradores pueden acceder
        flash('Acceso denegado: solo los administradores o usuarios pueden ver esta página.', 'danger')
        return redirect(url_for('index'))

    # Si es admin, podrán realizar acciones de administrador
    is_admin = session.get('role') == 'admin'

    products = get_products()
    return render_template('dashboard.html', products=products, is_admin=is_admin)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    flash('Cierre de sesión exitoso!', 'info')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
