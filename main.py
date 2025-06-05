import pandas as pd

from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from decouple import config
# from flasgger import Swagger, swag_from

from model_functions import anonymize, synthesize, balance
import bcrypt
import json

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = config('JWT_SECRET_KEY', default='secretkey123')
# app.config['SWAGGER'] = {
#     'title': 'SSStudio API',
#     'uiversion': 3
# }
jwt = JWTManager(app)
# swagger = Swagger(app)

users = {}

@app.route('/register', methods=['POST'])
# @swag_from('docs/register.yml')
def register():
    req = request.get_json()
    username = req.get('username')
    password = req.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if username in users:
        return jsonify({"error": "Username already exists"}), 409

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[username] = hashed
    return jsonify({"msg": "User registered"}), 201

@app.route('/login', methods=['POST'])
# @swag_from('docs/login.yml')
def login():
    req = request.get_json()
    username = req.get('username')
    password = req.get('password')

    hashed = users.get(username)
    if not hashed or not bcrypt.checkpw(password.encode('utf-8'), hashed):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=username)
    return jsonify({'token':access_token}), 200

@app.route('/ping', methods=['GET'])
def ping():
    return {"status": "ok"}, 200

@app.route('/test', methods=['GET'])
@jwt_required()
def test():
    current_user = get_jwt_identity()
    return jsonify({"msg": current_user}), 200

@app.route('/anonymize', methods=['POST'])
@jwt_required()
def anonymize_data():
    try:
        if request.content_type.startswith('application/json'):
            request_data = request.get_json()
            if 'data' not in request_data or 'configs' not in request_data:
                return jsonify({"error": "Missing 'data' or 'configs'"}), 400
            data = pd.DataFrame(request_data['data'])
            configs = request_data['configs']

        elif request.content_type.startswith('multipart/form-data'):
            if 'file' not in request.files or 'configs' not in request.form:
                return jsonify({"error": "Missing file or configs"}), 400

            csv_file = request.files['file']
            data = pd.read_csv(csv_file)

            try:
                configs = json.loads(request.form['configs'])
            except json.JSONDecodeError:
                return jsonify({"error": "Invalid JSON in 'configs'"}), 400

        else:
            return jsonify({"error": "Unsupported Content-Type"}), 415
        
        anonymized_data = anonymize(data, configs)
        return jsonify({"anonymized_data": anonymized_data.to_json(orient='records')}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/synthesize', methods=['POST'])
# @swag_from('docs/synthesize.yml')
@jwt_required()
def synthesize_data():
    try:
        if request.content_type.startswith('application/json'):
            request_data = request.get_json()
            if 'data' not in request_data or 'configs' not in request_data:
                return jsonify({"error": "Missing 'data' or 'configs'"}), 400
            data = pd.DataFrame(request_data['data'])
            configs = request_data['configs']

        elif request.content_type.startswith('multipart/form-data'):
            if 'file' not in request.files or 'configs' not in request.form:
                return jsonify({"error": "Missing file or configs"}), 400

            csv_file = request.files['file']
            data = pd.read_csv(csv_file)

            try:
                configs = json.loads(request.form['configs'])
            except json.JSONDecodeError:
                return jsonify({"error": "Invalid JSON in 'configs'"}), 400

        else:
            return jsonify({"error": "Unsupported Content-Type"}), 415

        synthesized_data = synthesize(data, configs)
        return jsonify({"synthesized_data": synthesized_data.to_json(orient='records')}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/balance', methods=['POST'])
@jwt_required()
def balance_data():
    try:
        if request.content_type.startswith('application/json'):
            request_data = request.get_json()
            if 'data' not in request_data or 'configs' not in request_data:
                return jsonify({"error": "Missing 'data' or 'configs'"}), 400
            data = pd.DataFrame(request_data['data'])
            configs = request_data['configs']

        elif request.content_type.startswith('multipart/form-data'):
            if 'file' not in request.files or 'configs' not in request.form:
                return jsonify({"error": "Missing file or configs"}), 400

            csv_file = request.files['file']
            data = pd.read_csv(csv_file)

            try:
                configs = json.loads(request.form['configs'])
            except json.JSONDecodeError:
                return jsonify({"error": "Invalid JSON in 'configs'"}), 400

        else:
            return jsonify({"error": "Unsupported Content-Type"}), 415

        balanced_data = balance(data, configs)
        return jsonify({"balanced_data": balanced_data.to_json(orient='records')}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    


app.run(debug=True)
