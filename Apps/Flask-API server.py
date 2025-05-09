from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import boto3

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
    user_id = data.get('UserId')
    name = data.get('Name')

    if not user_id or not name:
        return jsonify({'error': 'UserId and Name are required'}), 400

    try:
        table.put_item(Item={'UserId': user_id, 'Name': name})
        return jsonify({'message': 'User added successfully'}), 201
    except ClientError as e:
        return jsonify({'error': str(e)}), 500

# Update user data in Users table in DynamoDB
@app.route('/update_user/<user_id>', methods=['PUT'])
def update_user(user_id):
    try:
        data = request.get_json()
        update_expression = "SET " + ", ".join(f"#{k} = :{k}" for k in data.keys())
        expression_attr_names = {f"#{k}": k for k in data.keys()}
        expression_attr_values = {f":{k}": v for k, v in data.items()}

        response = table.update_item(
            Key={'UserId': user_id},
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attr_names,
            ExpressionAttributeValues=expression_attr_values,
            ReturnValues="UPDATED_NEW"
        )
        return jsonify({'message': 'User updated successfully!', 'updated_attributes': response['Attributes']}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# Search users in Users table in DynamoDB
@app.route('/search_users', methods=['GET'])
def search_users():
    try:
        name = request.args.get('name')
        response = table.scan(
            FilterExpression="contains(#name, :name)",
            ExpressionAttributeNames={"#name": "Name"},
            ExpressionAttributeValues={":name": name}
        )
        return jsonify(response['Items']), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # Run the Flask app
