from flask import Flask, jsonify, request # Removed make_response as it's not needed for this simple case
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import boto3
from botocore.exceptions import ClientError
from datetime import datetime
# Removed BadRequest as it's not used in the snippet
from flask_restx import Api, Resource, fields, reqparse, Namespace
from decimal import Decimal
from flask_cors import CORS # Keep this import
import logging

# Helper to convert Decimal to int/float for JSON serialization
def fix_decimals(obj):
    if isinstance(obj, list):
        return [fix_decimals(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: fix_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    return obj

logging.basicConfig(level=logging.INFO)

# Initialize Flask app
app = Flask(__name__)

# --- CORS Configuration (Place after app initialization) ---
CORS(app, supports_credentials=True, origins=[
    "http://ec2-13-60-86-85.eu-north-1.compute.amazonaws.com:3000"
])
# ---------------------------------------------------------


api = Api(app, version='1.0', title='User Management API',
          description='A simple User Management API')

# Define the users namespace
ns = api.namespace('users', description='User operations')
# Ensure this namespace is added if you're using it later, but the snippet only shows the /login route
# api.add_namespace(ns) # This line is present later in your full code, keep it there


# JWT configuration
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Replace with a secure key
jwt = JWTManager(app)

# Initialize DynamoDB client (Keep this)
# dynamodb = boto3.resource('dynamodb', region_name='eu-north-1')
# table = dynamodb.Table('Users')


# Login endpoint for user authentication
# Remove "OPTIONS" from methods here, Flask-CORS handles it automatically
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Replace with your own authentication logic
    if username == 'vladi' and password == 'Aa111111':
        access_token = create_access_token(identity=username)
        # Flask-CORS will add the necessary Access-Control-Allow-Origin header to this response
        return jsonify(access_token=access_token), 200
    else:
        # Flask-CORS will also add the necessary Access-Control-Allow-Origin header to this error response
        return jsonify({'error': 'Invalid username or password'}), 401

# ... rest of your routes and code ...

# Example of a protected route (Flask-CORS handles its OPTIONS as well)
# @app.route('/users_list', methods=['GET'])
# @jwt_required()
# def get_all_users():
#     # ... your logic ...
#     pass # Flask-CORS will add headers to this response


# Ensure you have api.add_namespace(ns) and api.add_namespace(epl_ns)
# and app.add_namespace(session_ns) etc. from your full code below
# the route definitions.

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000, debug=True)