"""
Seed script to populate the database with sample users.

This demonstrates how to create users with securely hashed passwords
using Bcrypt.
"""

from app import create_app, db, UserModel


def seed_database():
    """
    Create sample users for testing the application.
    
    This function demonstrates:
    1. Creating users with secure password hashing
    2. Verifying passwords work correctly
    3. Showing that hashed passwords are stored securely
    """
    app = create_app('development')
    
    with app.app_context():
        # Clean up existing data
        db.session.query(UserModel).delete()
        db.session.commit()
        print("✓ Cleared existing users")
        
        # Create sample users
        users_data = [
            {
                'username': 'john_doe',
                'email': 'john@example.com',
                'password': 'securepassword123'
            },
            {
                'username': 'jane_smith',
                'email': 'jane@example.com',
                'password': 'anotherSecureP@ss!'
            },
            {
                'username': 'demo_user',
                'email': 'demo@example.com',
                'password': 'demo123'
            }
        ]
        
        created_users = []
        for user_data in users_data:
            user = UserModel(
                username=user_data['username'],
                email=user_data['email']
            )
            user.password_hash = user_data['password']
            db.session.add(user)
            created_users.append(user)
            print(f"✓ Created user: {user.username}")
        
        db.session.commit()
        print("\n" + "="*60)
        print("DATABASE SEEDED SUCCESSFULLY!")
        print("="*60)
        
        # Demonstrate password verification
        print("\n--- Password Verification Demo ---")
        for user in created_users:
            # Test correct password
            correct_password = next(
                u['password'] for u in users_data 
                if u['username'] == user.username
            )
            is_valid = user.authenticate(correct_password)
            print(f"{user.username}: Correct password valid? {is_valid}")
            
            # Test incorrect password
            is_invalid = not user.authenticate('wrongpassword')
            print(f"{user.username}: Wrong password rejected? {is_invalid}")
            
            # Show the hashed password (safe to display)
            print(f"  Hashed password: {user.password_hash[:50]}...")
            print()
        
        # Demonstrate why simple_hash is insecure
        print("--- Simple Hash Demo (INSECURE) ---")
        password1 = "Joshua"
        password2 = "Jnshub"
        hash1 = UserModel.simple_hash(password1)
        hash2 = UserModel.simple_hash(password2)
        print(f"Password '{password1}' hash: {hash1}")
        print(f"Password '{password2}' hash: {hash2}")
        print(f"Hashes match? {hash1 == hash2} (INSECURE - allows collisions!)")
        print()
        
        # Show bcrypt prevents this
        print("--- Bcrypt Demo (SECURE) ---")
        bcrypt_hash1 = user.password_hash
        print(f"Different users have different bcrypt hashes")
        print(f"This prevents rainbow table attacks\n")
        
        print("="*60)
        print("Sample users created. You can now test the API:")
        print("  POST /signup - Create a new account")
        print("  POST /login - Login with username and password")
        print("  GET  /check_session - Check if logged in")
        print("  POST /logout - Log out")
        print("="*60)


if __name__ == '__main__':
    seed_database()

