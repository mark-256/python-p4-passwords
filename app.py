"""
Flask application for password protection demo.

This application demonstrates secure password handling using Bcrypt
for hashing and salting passwords in a Flask application.
"""

from flask import Flask, request, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from config import config

# Initialize extensions
db = SQLAlchemy()
bcrypt = Bcrypt()

def create_app(config_name='default'):
    """
    Create and configure the Flask application.
    
    Args:
        config_name: The configuration name to use (default: 'default')
    
    Returns:
        Configured Flask application instance
    """
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize extensions with app
    db.init_app(app)
    bcrypt.init_app(app)
    
    # Create API
    api = Api(app)
    
    # Add resources
    api.add_resource(Login, '/login')
    api.add_resource(Signup, '/signup')
    api.add_resource(User, '/users/<int:user_id>')
    api.add_resource(CheckSession, '/check_session')
    api.add_resource(Logout, '/logout')
    
    # Create tables within app context
    with app.app_context():
        db.create_all()
    
    return app


class UserModel(db.Model):
    """
    User model with secure password storage using Bcrypt.
    
    Attributes:
        id: Unique identifier for the user
        username: Unique username for the user
        email: User's email address
        _password_hash: Bcrypt hashed password (includes salt)
    """
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    _password_hash = db.Column(db.String(256), nullable=False)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    @property
    def password_hash(self):
        """
        Get the password hash.
        
        Returns:
            str: The bcrypt hashed password
        """
        return self._password_hash
    
    @password_hash.setter
    def password_hash(self, password):
        """
        Set the password hash using Bcrypt.
        
        This method automatically handles salting and hashing.
        
        Args:
            password: The plain text password to hash
        """
        # Generate bcrypt hash with salt
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8')
        ).decode('utf-8')
        self._password_hash = password_hash
    
    def authenticate(self, password):
        """
        Verify a password against the stored hash.
        
        Args:
            password: The plain text password to verify
            
        Returns:
            bool: True if password matches, False otherwise
        """
        return bcrypt.check_password_hash(
            self._password_hash, 
            password.encode('utf-8')
        )
    
    def to_dict(self):
        """
        Convert user to dictionary representation.
        
        Returns:
            dict: User data without password hash
        """
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email
        }
    
    @staticmethod
    def simple_hash(input_str):
        """
        Simple hash function for demonstration purposes only.
        
        WARNING: This is NOT secure for production use!
        Use bcrypt.generate_password_hash() instead.
        
        Args:
            input_str: String to hash
            
        Returns:
            int: Sum of byte values
        """
        return sum(bytearray(input_str, encoding='utf-8'))


class Login(Resource):
    """
    Resource for user login authentication.
    
    POST: Authenticate user with username and password
    """
    
    def post(self):
        """
        Handle login POST request.
        
        Expected JSON body:
        {
            "username": "user123",
            "password": "securepassword"
        }
        
        Returns:
            tuple: (response_dict, status_code)
        """
        data = request.get_json()
        
        if not data:
            return {'error': 'No data provided'}, 400
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return {'error': 'Username and password required'}, 400
        
        # Find user by username
        user = UserModel.query.filter(
            UserModel.username == username
        ).first()
        
        if not user:
            return {'error': 'Invalid username or password'}, 401
        
        # Verify password
        if user.authenticate(password):
            # Set session
            session['user_id'] = user.id
            return {
                'message': 'Login successful',
                'user': user.to_dict()
            }, 200
        
        return {'error': 'Invalid username or password'}, 401
    
    def get(self):
        """
        Get current user from session.
        
        Returns:
            tuple: (user_data or error, status_code)
        """
        user_id = session.get('user_id')
        
        if not user_id:
            return {'error': 'Not logged in'}, 401
        
        user = UserModel.query.get(user_id)
        
        if not user:
            return {'error': 'User not found'}, 404
        
        return user.to_dict(), 200


class Signup(Resource):
    """
    Resource for user registration.
    
    POST: Create a new user account
    """
    
    def post(self):
        """
        Handle signup POST request.
        
        Expected JSON body:
        {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "securepassword"
        }
        
        Returns:
            tuple: (response_dict, status_code)
        """
        data = request.get_json()
        
        if not data:
            return {'error': 'No data provided'}, 400
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        # Validate required fields
        if not username or not email or not password:
            return {'error': 'Username, email, and password required'}, 400
        
        # Check if username exists
        if UserModel.query.filter(
            UserModel.username == username
        ).first():
            return {'error': 'Username already exists'}, 409
        
        # Check if email exists
        if UserModel.query.filter(
            UserModel.email == email
        ).first():
            return {'error': 'Email already exists'}, 409
        
        # Create new user
        user = UserModel(
            username=username,
            email=email
        )
        user.password_hash = password  # This triggers the setter
        
        # Save to database
        db.session.add(user)
        db.session.commit()
        
        # Set session
        session['user_id'] = user.id
        
        return {
            'message': 'Account created successfully',
            'user': user.to_dict()
        }, 201


class User(Resource):
    """
    Resource for individual user operations.
    
    GET: Retrieve user by ID
    """
    
    def get(self, user_id):
        """
        Get user by ID.
        
        Args:
            user_id: The user's ID
            
        Returns:
            tuple: (user_data or error, status_code)
        """
        user = UserModel.query.get(user_id)
        
        if not user:
            return {'error': 'User not found'}, 404
        
        return user.to_dict(), 200


class CheckSession(Resource):
    """
    Resource to check if user is logged in.
    
    GET: Check current session
    """
    
    def get(self):
        """
        Check if user has an active session.
        
        Returns:
            tuple: (session_data or error, status_code)
        """
        user_id = session.get('user_id')
        
        if not user_id:
            return {'message': 'Not logged in', 'logged_in': False}, 200
        
        user = UserModel.query.get(user_id)
        
        if not user:
            return {'message': 'User not found', 'logged_in': False}, 404
        
        return {
            'message': 'Logged in',
            'logged_in': True,
            'user': user.to_dict()
        }, 200


class Logout(Resource):
    """
    Resource for user logout.
    
    POST: Log out the current user
    """
    
    def post(self):
        """
        Handle logout POST request.
        
        Returns:
            tuple: (response_dict, status_code)
        """
        session.pop('user_id', None)
        
        return {'message': 'Logged out successfully'}, 200


if __name__ == '__main__':
    # Create and run the app
    app = create_app('development')
    app.run(debug=True)

