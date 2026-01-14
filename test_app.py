"""
Test configuration for pytest.
"""

import pytest
from app import create_app, db, UserModel


@pytest.fixture
def app():
    """Create application for testing."""
    app = create_app('testing')
    app.config['TESTING'] = True
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def db_session(app):
    """Create database session for testing."""
    with app.app_context():
        yield db.session
        db.session.rollback()


class TestUserModel:
    """Tests for UserModel password hashing and authentication."""
    
    def test_password_hashing(self, app, db_session):
        """Test that passwords are properly hashed with bcrypt."""
        with app.app_context():
            user = UserModel(
                username='testuser',
                email='test@example.com'
            )
            user.password_hash = 'testpassword123'
            
            db_session.add(user)
            db_session.commit()
            
            # Password hash should not be plain text
            assert user._password_hash != 'testpassword123'
            
            # Password hash should be a bcrypt hash (starts with $2b$)
            assert user._password_hash.startswith('$2b$')
    
    def test_password_verification_correct(self, app, db_session):
        """Test that correct password is verified successfully."""
        with app.app_context():
            user = UserModel(
                username='testuser',
                email='test@example.com'
            )
            user.password_hash = 'testpassword123'
            
            db_session.add(user)
            db_session.commit()
            
            assert user.authenticate('testpassword123') is True
    
    def test_password_verification_incorrect(self, app, db_session):
        """Test that incorrect password is rejected."""
        with app.app_context():
            user = UserModel(
                username='testuser',
                email='test@example.com'
            )
            user.password_hash = 'testpassword123'
            
            assert user.authenticate('wrongpassword') is False
    
    def test_different_passwords_produce_different_hashes(self, app, db_session):
        """Test that different passwords produce different hashes."""
        with app.app_context():
            user1 = UserModel(username='user1', email='user1@example.com')
            user1.password_hash = 'password123'
            
            user2 = UserModel(username='user2', email='user2@example.com')
            user2.password_hash = 'password123'
            
            # Same password but different users should have different hashes (salt)
            assert user1._password_hash != user2._password_hash
    
    def test_user_to_dict(self, app, db_session):
        """Test user serialization to dictionary."""
        with app.app_context():
            user = UserModel(
                username='testuser',
                email='test@example.com'
            )
            user.password_hash = 'testpassword'
            
            user_dict = user.to_dict()
            
            assert 'id' in user_dict
            assert user_dict['username'] == 'testuser'
            assert user_dict['email'] == 'test@example.com'
            # Password hash should not be in the dictionary
            assert 'password' not in user_dict
            assert '_password_hash' not in user_dict


class TestSignup:
    """Tests for Signup API endpoint."""
    
    def test_signup_success(self, client, app, db_session):
        """Test successful user signup."""
        with app.app_context():
            response = client.post('/signup', json={
                'username': 'newuser',
                'email': 'newuser@example.com',
                'password': 'securepassword123'
            })
            
            assert response.status_code == 201
            data = response.get_json()
            assert 'user' in data
            assert data['user']['username'] == 'newuser'
            assert data['user']['email'] == 'newuser@example.com'
    
    def test_signup_duplicate_username(self, client, app, db_session):
        """Test signup with existing username fails."""
        with app.app_context():
            # Create first user
            user = UserModel(username='existing', email='existing@test.com')
            user.password_hash = 'password'
            db_session.add(user)
            db_session.commit()
            
            # Try to create second user with same username
            response = client.post('/signup', json={
                'username': 'existing',
                'email': 'different@example.com',
                'password': 'password123'
            })
            
            assert response.status_code == 409
            data = response.get_json()
            assert 'Username already exists' in data['error']
    
    def test_signup_duplicate_email(self, client, app, db_session):
        """Test signup with existing email fails."""
        with app.app_context():
            # Create first user
            user = UserModel(username='user1', email='same@example.com')
            user.password_hash = 'password'
            db_session.add(user)
            db_session.commit()
            
            # Try to create second user with same email
            response = client.post('/signup', json={
                'username': 'different',
                'email': 'same@example.com',
                'password': 'password123'
            })
            
            assert response.status_code == 409
            data = response.get_json()
            assert 'Email already exists' in data['error']
    
    def test_signup_missing_fields(self, client, app, db_session):
        """Test signup with missing required fields fails."""
        with app.app_context():
            response = client.post('/signup', json={
                'username': 'testuser'
                # Missing email and password
            })
            
            assert response.status_code == 400


class TestLogin:
    """Tests for Login API endpoint."""
    
    def test_login_success(self, client, app, db_session):
        """Test successful login."""
        with app.app_context():
            # Create user
            user = UserModel(username='testuser', email='test@example.com')
            user.password_hash = 'testpassword123'
            db_session.add(user)
            db_session.commit()
            
            # Login
            response = client.post('/login', json={
                'username': 'testuser',
                'password': 'testpassword123'
            })
            
            assert response.status_code == 200
            data = response.get_json()
            assert 'user' in data
            assert data['user']['username'] == 'testuser'
    
    def test_login_wrong_password(self, client, app, db_session):
        """Test login with wrong password fails."""
        with app.app_context():
            # Create user
            user = UserModel(username='testuser', email='test@example.com')
            user.password_hash = 'testpassword123'
            db_session.add(user)
            db_session.commit()
            
            # Login with wrong password
            response = client.post('/login', json={
                'username': 'testuser',
                'password': 'wrongpassword'
            })
            
            assert response.status_code == 401
    
    def test_login_nonexistent_user(self, client, app, db_session):
        """Test login with nonexistent user fails."""
        with app.app_context():
            response = client.post('/login', json={
                'username': 'nonexistent',
                'password': 'anypassword'
            })
            
            assert response.status_code == 401


class TestSession:
    """Tests for session management."""
    
    def test_check_session_not_logged_in(self, client, app, db_session):
        """Test checking session when not logged in."""
        with app.app_context():
            response = client.get('/check_session')
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['logged_in'] is False
    
    def test_check_session_logged_in(self, client, app, db_session):
        """Test checking session when logged in."""
        with app.app_context():
            # Create and login user
            user = UserModel(username='testuser', email='test@example.com')
            user.password_hash = 'testpassword123'
            db_session.add(user)
            db_session.commit()
            
            # Login first
            client.post('/login', json={
                'username': 'testuser',
                'password': 'testpassword123'
            })
            
            # Check session
            response = client.get('/check_session')
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['logged_in'] is True
            assert data['user']['username'] == 'testuser'
    
    def test_logout(self, client, app, db_session):
        """Test user logout."""
        with app.app_context():
            # Create and login user
            user = UserModel(username='testuser', email='test@example.com')
            user.password_hash = 'testpassword123'
            db_session.add(user)
            db_session.commit()
            
            # Login first
            client.post('/login', json={
                'username': 'testuser',
                'password': 'testpassword123'
            })
            
            # Logout
            response = client.post('/logout')
            
            assert response.status_code == 200
            
            # Verify logged out
            response = client.get('/check_session')
            data = response.get_json()
            assert data['logged_in'] is False


class TestSecurity:
    """Tests for security features."""
    
    def test_simple_hash_is_insecure(self, app, db_session):
        """Demonstrate that simple_hash is insecure (for documentation)."""
        with app.app_context():
            # This test documents why simple_hash should not be used
            # for password storage - it allows trivial collisions
            
            hash1 = UserModel.simple_hash('Joshua')
            hash2 = UserModel.simple_hash('Peter')
            
            # Different passwords should have different hashes
            # but the simple hash can have collisions
            # This test just documents the behavior
            assert hash1 == sum(bytearray('Joshua', encoding='utf-8'))
            assert hash2 == sum(bytearray('Peter', encoding='utf-8'))
            assert hash1 != hash2  # These produce different sums
            
            # Note: The point is that bcrypt.hash should be used instead
            # for any real password storage
    
    def test_bcrypt_prevents_rainbow_tables(self, app, db_session):
        """Test that bcrypt prevents rainbow table attacks."""
        with app.app_context():
            # Create users with same password
            user1 = UserModel(username='user1', email='user1@example.com')
            user1.password_hash = 'samepassword'
            
            user2 = UserModel(username='user2', email='user2@example.com')
            user2.password_hash = 'samepassword'
            
            # Hashes should be different due to unique salts
            assert user1._password_hash != user2._password_hash
            
            # Both should still authenticate with the same password
            assert user1.authenticate('samepassword') is True
            assert user2.authenticate('samepassword') is True

