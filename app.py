from flask import Flask, current_app, request, jsonify, render_template, redirect, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from librouteros import connect, plain
from librouteros.exceptions import LibRouterosError
from flask_cors import CORS

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'fernando221237'  # Cambia esto por una clave secreta fuerte
jwt = JWTManager(app)
CORS(app)

# Almacén global para IDs de usuarios
user_ids = []

@app.route('/')
def login():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def handle_login():
    username = request.form.get('username')
    password = request.form.get('password')
    ip_address = request.form.get('ip_address')

    if not username or not password or not ip_address:
        return jsonify(status='error', message='All fields are required'), 400

    try:
        api = connect(username=username, password=password, host=ip_address)
        access_token = create_access_token(identity={'username': username, 'password': password, 'ip_address': ip_address})
        response = jsonify(status='success', data={'token': access_token})
        response.headers['Authorization'] = f'Bearer {access_token}'
        return response
    except LibRouterosError as e:
        return jsonify(status='error', message=str(e)), 401

@app.route('/create_user')
def create_user_page():
    return render_template('create_user.html')

@app.route('/create_user', methods=['POST'])
@jwt_required()
def create_user():
    auth_data = get_jwt_identity()
    new_username = request.form.get('new_username')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    group = request.form.get('group')
    allow_address = request.form.get('allow_address')
    comment = request.form.get('comment')
    allow = request.form.get('allow')

    if not new_username or not new_password or not confirm_password or not group or not allow_address:
        return jsonify(status='error', message='All fields are required'), 400

    if new_password != confirm_password:
        return jsonify(status='error', message='Passwords do not match'), 400

    try:
        api = connect(username=auth_data['username'], password=auth_data['password'], host=auth_data['ip_address'])
        user_details = {
            'name': new_username,
            'password': new_password,
            'group': group,
            'address': allow_address,
            'comment': comment,
            'disabled': 'no' if allow == 'yes' else 'yes'
        }
        new_user = api.path("user").add(**user_details)
        new_user_id = new_user[0]['.id']  # Obtén el ID del nuevo usuario
        user_ids.append(new_user_id)  # Guarda el ID en la lista global
        return jsonify(status='success', message='User created successfully', user_id=new_user_id)
    except LibRouterosError as e:
        return jsonify(status='error', message=f'Mikrotik API error: {str(e)}'), 400
    except Exception as e:
        current_app.logger.error(f"General error: {e}")
        return jsonify(status='error', message=f"General error: {str(e)}"), 500

@app.route('/user_management')
def user_management():
    return render_template('manage_users.html')

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    auth_data = get_jwt_identity()

    try:
        api = connect(username=auth_data['username'], password=auth_data['password'], host=auth_data['ip_address'])
        users = list(api(cmd='/user/print'))
        return jsonify(status='success', users=users)
    except LibRouterosError as e:
        return jsonify(status='error', message=str(e)), 400

@app.route('/delete_user', methods=['POST'])
@jwt_required()
def delete_user():
    auth_data = get_jwt_identity()
    user_id = request.form.get('user_id')

    if not user_id:
        return jsonify(status='error', message='User ID is required'), 400

    try:
        api = connect(username=auth_data['username'], password=auth_data['password'], host=auth_data['ip_address'])
        api.path("user").remove(user_id)
        return jsonify(status='success', message='User deleted successfully')
    except LibRouterosError as e:
        return jsonify(status='error', message=str(e)), 400
    except Exception as e:
        current_app.logger.error(f"General error: {e}")
        return jsonify(status='error', message=f"General error: {str(e)}"), 500

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    auth_data = get_jwt_identity()

    try:
        api = connect(username=auth_data['username'], password=auth_data['password'], host=auth_data['ip_address'])
        # Logout logic for Mikrotik can be added here if applicable
        return jsonify(status='success', message='Logged out successfully')
    except LibRouterosError as e:
        return jsonify(status='error', message=str(e)), 400

if __name__ == '__main__':
    app.run(debug=True)
