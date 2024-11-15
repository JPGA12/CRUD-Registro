from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import os
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"
DATA_FILE = 'data.json'
login_attempts = {}

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
        print(f"Datos guardados en {DATA_FILE}: {data}")

# Funciones de validación
def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

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

# CRUD de productos
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

# Rutas de la aplicación
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = read_user(username)

    if username in login_attempts:
        attempts, lock_until = login_attempts[username]
        if datetime.now() < lock_until:
            session['error'] = 'Usuario bloqueado temporalmente. Intente más tarde.'
            return redirect(url_for('index'))

    if user and check_password_hash(user['password'], password):
        session['username'] = username
        session['role'] = user.get("role", "user")
        login_attempts.pop(username, None)
        flash('Inicio de sesión exitoso!', 'success')
        return redirect(url_for('dashboard'))

    session['error'] = 'Credenciales incorrectas'
    return redirect(url_for('index'))

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)

@app.route('/register')
def register_page():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

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

        if new_password != confirm_password:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('reset_password'))

        user = read_user(username)
        if not user:
            flash('El usuario no existe.', 'danger')
            return redirect(url_for('reset_password'))

        hashed_password = generate_password_hash(new_password)
        user['password'] = hashed_password

        data = load_data()
        for i, existing_user in enumerate(data['users']):
            if existing_user['username'] == username:
                data['users'][i] = user
                break

        save_data(data)
        flash('Contraseña restablecida exitosamente!', 'success')
        return redirect(url_for('index'))

    return render_template('reset_password.html')


@app.route('/add_product', methods=['POST'])
def add_product_route():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Acceso denegado: solo los administradores pueden agregar productos.', 'danger')
        return redirect(url_for('index'))

    # Validar que el precio y la cantidad sean números positivos
    try:
        price = float(request.form['price'])
        quantity = int(request.form['quantity'])

        if price <= 0 or quantity <= 0:
            flash('El precio y la cantidad deben ser números positivos.', 'danger')
            return redirect(url_for('dashboard'))

    except ValueError:
        flash('El precio debe ser un número decimal y la cantidad un número entero.', 'danger')
        return redirect(url_for('dashboard'))

    # Obtener el nombre del producto
    name = request.form['name']

    # Agregar el producto
    add_product(name, price, quantity)
    flash('Producto agregado exitosamente!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product_route(product_id):
    data = load_data()
    data['products'] = [product for product in data['products'] if product['id'] != product_id]
    save_data(data)
    flash('Producto eliminado exitosamente!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
def edit_product_page(product_id):
    data = load_data()
    product = next((p for p in data["products"] if p["id"] == product_id), None)

    if not product:
        flash("Producto no encontrado.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Validación de precio y cantidad para asegurar valores numéricos positivos
        try:
            price = float(request.form['price'])
            quantity = int(request.form['quantity'])

            if price <= 0 or quantity <= 0:
                flash('El precio y la cantidad deben ser números positivos.', 'danger')
                return redirect(url_for('edit_product_page', product_id=product_id))

        except ValueError:
            flash('El precio debe ser un número decimal y la cantidad un número entero.', 'danger')
            return redirect(url_for('edit_product_page', product_id=product_id))

        # Actualizar los datos del producto si las validaciones son correctas
        product["name"] = request.form['name']
        product["price"] = price
        product["quantity"] = quantity
        save_data(data)
        flash("Producto actualizado con éxito.", "success")
        return redirect(url_for('dashboard'))

    return render_template('edit_product.html', product=product)


# Función para obtener productos
def get_products():
    data = load_data()  # Cargar los datos desde el archivo
    return data["products"]  # Devolver la lista de productos

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))

    if session.get('role') not in ['admin', 'user']:
        flash('Acceso denegado: solo los administradores o usuarios pueden ver esta página.', 'danger')
        return redirect(url_for('index'))

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
