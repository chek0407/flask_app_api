from flask import Flask
from flask_restx import Api, Resource
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

app = Flask(__name__)

# JWT config
app.config["JWT_SECRET_KEY"] = "secret-key"
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

jwt = JWTManager(app)

# Swagger config with Authorize button
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': 'Paste token like: **Bearer <your_token>**'
    }
}

api = Api(
    app,
    version="1.0",
    title="EPL API Auth Test",
    description="Test JWT Auth with Swagger UI",
    doc="/",  # Swagger UI path
    authorizations=authorizations,
    #security='Bearer'  # Applies to all unless overridden
)

ns = api.namespace('test', description='Test namespace')

@ns.route('/secure')
class Secure(Resource):
    @api.doc(security='Bearer')  # Tells Swagger this route uses auth
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return {"message": f"Hello, {current_user}"}

@ns.route('/login')
class Login(Resource):
    def post(self):
        token = create_access_token(identity="vladi")
        return {"token": token}

if __name__ == '__main__':
    app.run(debug=True)
