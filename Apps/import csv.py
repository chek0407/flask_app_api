import csv
import io
from flask import request

# Create user(s) in DynamoDB
@app.route('/add_user', methods=['POST'])
@jwt_required()
def add_user():
    current_user = get_jwt_identity()

    # Check if request contains a file (CSV upload)
    if 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file uploaded'}), 400

        # Read CSV content
        stream = io.StringIO(file.stream.read().decode("UTF8"))
        csv_reader = csv.DictReader(stream)
        
        users = []
        errors = []

        for row in csv_reader:
            user_id = row.get('UserId')
            name = row.get('Name')

            if not user_id or not name:
                errors.append({'error': 'UserId and Name are required', 'user': row})
                continue

            item = {
                'UserId': user_id,
                'Name': name,
                'Email': row.get('Email', 'unknown@example.com'),
                'Status': row.get('Status', 'active'),
                'Preferences': row.get('Preferences', '{"theme": "light", "notifications": true}'),
                'CreatedAt': datetime.utcnow().isoformat()
            }

            try:
                table.put_item(Item=item)
                users.append(item)
            except ClientError as e:
                errors.append({'error': str(e), 'user': row})

        response = {'message': 'Users added from CSV successfully', 'users': users}
        if errors:
            response['errors'] = errors

        return jsonify(response), (201 if users else 400)

    # Otherwise, process a single JSON user
    data = request.get_json()
    if isinstance(data, dict):  
        user_id = data.get('UserId')
        name = data.get('Name')

        if not user_id or not name:
            return jsonify({'error': 'UserId and Name are required'}), 400

        item = {
            'UserId': user_id,
            'Name': name,
            'Email': data.get('Email', 'unknown@example.com'),
            'Status': data.get('Status', 'active'),
            'Preferences': data.get('Preferences', {"theme": "light", "notifications": True}),
            'CreatedAt': datetime.utcnow().isoformat()
        }

        try:
            table.put_item(Item=item)
            return jsonify({'message': 'User added successfully', 'user': item}), 201
        except ClientError as e:
            return jsonify({'error': str(e)}), 500

    return jsonify({'error': 'Invalid request format'}), 400
