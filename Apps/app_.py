from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import boto3 
from botocore.exceptions import ClientError
from datetime import datetime
from werkzeug.exceptions import BadRequest

# Initialize Flask app
app = Flask(__name__)

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
            return jsonify(response['Items']), 200
        else:
            return jsonify({'message': 'No users found'}), 404
    except ClientError as e:
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
    
    # Loop through each field and prepare update expression and values
    for key, value in data.items():
        update_expression += f"{key} = :{key}, "
        expression_attribute_values[f":{key}"] = value

    # Remove trailing comma and space from update expression
    update_expression = update_expression.rstrip(", ")

    try:
        # Perform the update operation in DynamoDB
        response = table.update_item(
            Key={'UserId': user_id},  # Assuming 'UserId' is the primary key
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues="UPDATED_NEW"  # Only return updated attributes
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
    except BadRequest as e:
        # Handle bad request errors (e.g., malformed JSON)
        return jsonify({'error': str(e)}), 400
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # Run the Flask app
