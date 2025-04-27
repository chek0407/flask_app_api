from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import boto3
from botocore.exceptions import ClientError
from datetime import datetime
from werkzeug.exceptions import BadRequest
from flask_restx import Api, Resource, fields, reqparse, Namespace
import logging

logging.basicConfig(level=logging.INFO)

# Initialize Flask app
app = Flask(__name__)
api = Api(app, version='1.0', title='User Management API',
          description='A simple User Management API')

# Define the users namespace
ns = api.namespace('users', description='User operations')
api.add_namespace(ns, path='/users')

# JWT configuration
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Replace with a secure key
jwt = JWTManager(app)

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb', region_name='eu-north-1')  # Change region if needed
table = dynamodb.Table('Users')  # Your DynamoDB table name

# Login endpoint for user authentication
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

# Replace with your own authentication logic
    if username == 'vladi' and password == 'Aa111111':
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 401

# Protected endpoint to get user data
@app.route('/get_user/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    current_user = get_jwt_identity()  # Identity of the logged-in user
    try:
        response = table.get_item(Key={'UserId': user_id})
        if 'Item' in response:
            return jsonify(response['Item']), 200
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Retrieve all users from DynamoDB
@app.route('/users_list', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user = get_jwt_identity()
    try:
        response = table.scan()  # Retrieve all items from the table
        
        if 'Items' in response:
            users = response['Items']
            # 🚀 Force a test log
            logging.info("🚀 DEBUG: API is running", flush=True)
            # Log users BEFORE sorting
            print("Users BEFORE sorting:", users, flush=True)

            # Sorting users by UserId
            users.sort(key=lambda x: x.get('UserId', '') or 'zzz')

            # Log users AFTER sorting
            print("Users AFTER sorting:", users, flush=True)

            return jsonify(users), 200
        else:
            return jsonify({'message': 'No users found'}), 404
    except ClientError as e:
        print("DynamoDB Error:", str(e), flush=True)
        return jsonify({'error': str(e)}), 500


# Create a new user in DynamoDB
@app.route('/add_user', methods=['POST'])
@jwt_required()
def add_user():
    current_user = get_jwt_identity()
    data = request.get_json()

    # Validate required fields
    user_id = data.get('UserId')
    name = data.get('Name')

    if not user_id or not name:
        return jsonify({'error': 'UserId and Name are required'}), 400

    # Add default fields if they are not provided
    item = {
        'UserId': user_id,
        'Name': name,
        'Email': data.get('Email', 'unknown@example.com'),  # Default Email
        'Status': data.get('Status', 'active'),  # Default Status
        'Preferences': data.get('Preferences', {"theme": "light", "notifications": True}),  # Default Preferences
        'CreatedAt': data.get('CreatedAt', datetime.utcnow().isoformat())  # Dynamic timestamp
    }

    # Include any additional dynamic fields
    for key, value in data.items():
        if key not in item:
            item[key] = value

    try:
        table.put_item(Item=item)
        return jsonify({'message': 'User added successfully', 'user': item}), 201
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

# Update user data in Users table in DynamoDB
@app.route('/update_user/<user_id>', methods=['PUT'])
@jwt_required()  # Protect the endpoint with JWT authentication
def update_user(user_id):
    current_user = get_jwt_identity()  # Retrieve the identity of the currently authenticated user
    data = request.get_json()

    # Validate the input data
    if not data:
        return jsonify({'error': 'Request body is empty'}), 400

    # Construct the update expression dynamically
    update_expression = "SET "
    expression_attribute_values = {}
    for key, value in data.items():
        update_expression += f"{key} = :{key}, "
        expression_attribute_values[f":{key}"] = value

    # Remove trailing comma and space
    update_expression = update_expression.rstrip(", ")

    try:
        # Perform the update operation
        response = table.update_item(
            Key={'UserId': user_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues="UPDATED_NEW"
        )
	# Return success response with updated attributes
        updated_attributes = response.get('Attributes', {})
        if updated_attributes:
            return jsonify({
                'message': 'User updated successfully',
                'updatedAttributes': updated_attributes
            }), 200
        else:
            return jsonify({'message': 'No attributes updated'}), 200

    except ClientError as e:
        # Handle DynamoDB client errors
        error_message = e.response['Error'].get('Message', 'Unknown error')
        return jsonify({'error': error_message}), 500
    except Exception as e:
        # General exception handling
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

# Remove user by DELETE from the table
@app.route('/delete_user/<user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    # Get the current authenticated user (optional for auditing)
    current_user = get_jwt_identity()

    try:
        # Delete the user from DynamoDB using the UserId
        response = table.delete_item(
            Key={'UserId': user_id}
        )

        # Check if the item was deleted successfully
        if 'Attributes' not in response:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'message': f'User {user_id} deleted successfully'}), 200
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

# Search users in Users table in DynamoDB
@app.route('/search_users', methods=['GET'])
@jwt_required()  # Optional: Protect the endpoint with JWT authentication
def search_users():
    current_user = get_jwt_identity()  # Retrieve the identity of the currently authenticated user (optional)
    
    # Get query parameters from the URL
    name = request.args.get('name', None)
    email = request.args.get('email', None)

    # If no parameters are provided, return an error
    if not name and not email:
        return jsonify({'error': 'At least one search parameter (name or email) must be provided'}), 400

    try:
        if name:  # Search by name
            response = table.scan(
                FilterExpression="contains(#Name, :name)",
                ExpressionAttributeNames={"#Name": "Name"},
                ExpressionAttributeValues={":name": name}
            )
        elif email:  # Search by email
            response = table.scan(
                FilterExpression="contains(#Email, :email)",
                ExpressionAttributeNames={"#Email": "Email"},
                ExpressionAttributeValues={":email": email}
            )
        else:
            # Add additional logic if searching for multiple fields at once
            pass

        # Return the matching users
        items = response.get('Items', [])
        if not items:
            return jsonify({'message': 'No users found'}), 404

        return jsonify({'message': 'Users found', 'users': items}), 200

    except ClientError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500


# Define a namespace for your API
ns = api.namespace('users', description='User operations')


# Define models for request/response validation and documentation
user_model = api.model('User', {
    'UserName': fields.String(required=False, description='The user name'),
    'Email': fields.String(required=True, description='The user email'),
    'Phone': fields.String(required=False, description='The user phone'),
    'Address': fields.String(required=False, description='The user address'),
    'Status': fields.String(required=False, description='The user status')
})

update_user_model = api.model('UpdateUser', {
    'UserName': fields.String(required=False, description='The user name'),
    'Email': fields.String(required=False, description='The user email'),
    'Phone': fields.String(required=False, description='The user phone'),
    'Address': fields.String(required=False, description='The user address'),
    'Status': fields.String(required=False, description='The user status')
})

# Define a new model for the login request
login_model = api.model('UserLogin', {
    'username': fields.String(required=True, description='The username'),
    'password': fields.String(required=True, description='The user password')
})

# Define a new model for searching users
search_user_model = api.model('SearchUser', {
    'name': fields.String(required=False, description='The name to search for'),
    'email': fields.String(required=False, description='The email to search for')
})

# Mock DynamoDB table (replace with actual table logic)
mock_table = {}

# Define API endpoints
@ns.route('/<string:user_id>')
@ns.param('user_id', 'The user identifier')
class UserResource(Resource):
    @ns.doc('get_user')
    @ns.response(200, 'Success')
    @ns.response(404, 'User not found')
    def get(self, user_id):
        """Fetch a user by ID"""
        user = mock_table.get(user_id)
        if not user:
            api.abort(404, f"User {user_id} not found")
        return jsonify(user)

    @ns.doc('update_user')
    @ns.expect(update_user_model)
    @ns.response(200, 'User updated successfully')
    @ns.response(400, 'Bad request')
    def put(self, user_id):
        """Update a user by ID"""
        if user_id not in mock_table:
            api.abort(404, f"User {user_id} not found")

        # Update user with provided fields
        data = request.json
        for key, value in data.items():
            mock_table[user_id][key] = value
        return jsonify({"message": "User updated successfully", "updatedUser": mock_table[user_id]})


@ns.route('/')
class UserList(Resource):
    @ns.doc('list_users')
    def get(self):
        """List all users"""
        return jsonify(list(mock_table.values()))

    @ns.doc('add_user')
    @ns.expect(user_model)
    @ns.response(201, 'User created successfully')
    def post(self):
        """Create a new user"""
        data = request.json
        user_id = str(len(mock_table) + 1)  # Simple auto-incrementing ID
        mock_table[user_id] = data
        return jsonify({"message": "User created successfully", "userId": user_id}), 201

# Add Login Endpoint
@api.route('/login')
class UserLogin(Resource):
    @api.expect(login_model)
    def post(self):
        """Login a user"""
        data = request.json
        username = data.get ('username')
        password = data.get ('password')
        # Logic for login (you can validate the user here, e.g., check user credentials)
        if username == "vladi" and password == "Aa111111":
            return jsonify({"message": "Login successful", "user": username}), 200
        else:
            return jsonify({"message": "Invalid credentials"}), 400

        return {'message': 'Login successful'}


# Add Delete User Endpoint
@ns.route('/delete/<string:user_id>')
class DeleteUser(Resource):
    @ns.doc('delete_user')
    @ns.response(200, 'User deleted successfully')
    @ns.response(404, 'User not found')
    def delete(self, user_id):
        """Delete a user by ID"""
        if user_id in mock_table:
            del mock_table[user_id]
            return {'message': 'User deleted successfully'}
        else:
            api.abort(404, f"User {user_id} not found")


# Add Search User Endpoint
@ns.route('/search')
class UserSearch(Resource):
    @ns.doc('search_users')
    @ns.expect(search_user_model)
    @ns.response(200, 'Users found')
    @ns.response(400, 'Bad request')
    @ns.response(404, 'No users found')
    def get(self):
        """Search users by name or email"""
        name = request.args.get('name', None)
        email = request.args.get('email', None)

        if not name and not email:
            return {'error': 'At least one search parameter (name or email) must be provided'}, 400

        try:
            if name:
                response = table.scan(
                    FilterExpression="contains(#Name, :name)",
                    ExpressionAttributeNames={"#Name": "Name"},
                    ExpressionAttributeValues={":name": name}
                )
            elif email:
                response = table.scan(
                    FilterExpression="contains(#Email, :email)",
                    ExpressionAttributeNames={"#Email": "Email"},
                    ExpressionAttributeValues={":email": email}
                )
            items = response.get('Items', [])
            if not items:
                return {'message': 'No users found'}, 404

            return {'message': 'Users found', 'users': items}, 200

        except ClientError as e:
            return {'error': str(e)}, 500
        except Exception as e:
            return {'error': f'An unexpected error occurred: {str(e)}'}, 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)  # Run the Flask app
