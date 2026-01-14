# Password Protection with Flask and Bcrypt

A comprehensive demonstration of secure password handling in Flask applications using Bcrypt for hashing and salting.

## Learning Goals

- ✅ Explain why it's a bad idea to store passwords in plaintext
- ✅ Write code to store and verify hashed, salted passwords
- ✅ Use SQLAlchemy and Bcrypt to store and authenticate user login credentials securely

---

## Overview

This project demonstrates secure password management in Flask applications:

1. **Password Hashing**: Using Bcrypt to securely hash passwords
2. **Salting**: Automatic salt generation to prevent rainbow table attacks
3. **Authentication**: Secure login verification
4. **Session Management**: User session handling

## Why Bcrypt?

Bcrypt is ideal for password hashing because:

1. **Similar strings hash to very different values** - Prevents pattern analysis
2. **Cryptographic security** - Computationally difficult to reverse
3. **Designed to be slow** - Makes brute force attacks impractical
4. **Built-in salting** - Each hash includes a unique salt

## Quick Start

### Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Application

```bash
# Start the Flask development server
python app.py
```

The application will start at `http://localhost:5000`

### Seeding the Database

```bash
# Create sample users with hashed passwords
python seed.py
```

---

## API Endpoints

### Sign Up - Create New Account

```http
POST /signup
Content-Type: application/json

{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "securepassword123"
}
```

**Response (201 Created):**

```json
{
  "message": "Account created successfully",
  "user": {
    "id": 1,
    "username": "newuser",
    "email": "newuser@example.com"
  }
}
```

### Login - Authenticate User

```http
POST /login
Content-Type: application/json

{
    "username": "newuser",
    "password": "securepassword123"
}
```

**Response (200 OK):**

```json
{
  "message": "Login successful",
  "user": {
    "id": 1,
    "username": "newuser",
    "email": "newuser@example.com"
  }
}
```

**Response (401 Unauthorized):**

```json
{
  "error": "Invalid username or password"
}
```

### Check Session - Verify Authentication

```http
GET /check_session
```

**Response (200 OK - Logged In):**

```json
{
  "message": "Logged in",
  "logged_in": true,
  "user": {
    "id": 1,
    "username": "newuser",
    "email": "newuser@example.com"
  }
}
```

**Response (200 OK - Not Logged In):**

```json
{
  "message": "Not logged in",
  "logged_in": false
}
```

### Logout - End Session

```http
POST /logout
```

**Response (200 OK):**

```json
{
  "message": "Logged out successfully"
}
```

### Get User by ID

```http
GET /users/1
```

**Response (200 OK):**

```json
{
  "id": 1,
  "username": "newuser",
  "email": "newuser@example.com"
}
```

---

## Code Structure

```
python-p4-passwords/
├── app.py           # Main Flask application with User model
├── config.py        # Configuration settings
├── seed.py          # Database seeding script
├── requirements.txt # Python dependencies
├── README.md        # This file
└── LICENSE.md       # License information
```

### Key Components

#### User Model (`app.py`)

```python
class UserModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    _password_hash = db.Column(db.String(256))

    @property
    def password_hash(self):
        return self._password_hash

    @password_hash.setter
    def password_hash(self, password):
        # Bcrypt automatically handles salting and hashing
        password_hash = bcrypt.generate_password_hash(
            password.encode('utf-8')
        ).decode('utf-8')
        self._password_hash = password_hash

    def authenticate(self, password):
        # Bcrypt automatically extracts salt and verifies
        return bcrypt.check_password_hash(
            self._password_hash,
            password.encode('utf-8')
        )
```

---

## Security Best Practices

### ✅ DO

- Always use Bcrypt (or similar vetted password hashing libraries)
- Use unique salts for each password (Bcrypt does this automatically)
- Hash passwords on the server side
- Use HTTPS in production
- Implement rate limiting on login attempts

### ❌ DON'T

- Store passwords in plain text
- Use custom hash functions for passwords
- Use fast hash functions (MD5, SHA-256) for passwords
- Transmit passwords in plain text
- Use the same salt for all passwords

---

## Testing with cURL

### Sign Up

```bash
curl -X POST http://localhost:5000/signup \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "email": "test@example.com", "password": "testpass123"}'
```

### Login

```bash
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass123"}'
```

### Check Session

```bash
curl http://localhost:5000/check_session
```

### Logout

```bash
curl -X POST http://localhost:5000/logout
```

---

## Key Vocabulary

- **Hashing**: Converting a password into a fixed-length string using a mathematical function
- **Salting**: Adding random data to a password before hashing to prevent rainbow table attacks
- **Authentication**: Verifying a user's identity (logging in)
- **Session**: The time between logging in and logging out
- **Rainbow Table**: Precomputed table of hash values used to crack passwords

---

## Resources

- [Flask-Bcrypt Documentation](https://flask-bcrypt.readthedocs.io/)
- [Bcrypt Wikipedia](https://en.wikipedia.org/wiki/Bcrypt)
- [Rainbow Tables](https://en.wikipedia.org/wiki/Rainbow_table)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

## License

See [LICENSE.md](LICENSE.md) for details.
