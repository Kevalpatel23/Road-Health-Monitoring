# Import necessary libraries for the application
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from datetime import datetime, timedelta
import os
import sqlite3
import random
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Initialize the Flask application
app = Flask(__name__, template_folder="templates")
app.secret_key = 'KEval@123'  # Secret key for session management

# Define the upload folder for images
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create the upload folder if it doesn't exist
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  # Set the upload folder in app config
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Set maximum content length to 5 MB
print("Template folder path:", os.path.abspath("templates"))  # Print the template folder path for debugging

# Dummy users with hashed passwords for authentication
users = [
    {"username": "admin", "password": generate_password_hash("admin123"), "role": "admin"},
    {"username": "user", "password": generate_password_hash("user123"), "role": "user"}
]

# Simulated database for roads with random data
roads = []
for i in range(1, 21):
    roads.append({
        'id': i,
        'name': f'Road {i}',  # Name of the road
        'condition': random.choice(['Good', 'Fair', 'Poor', 'Critical']),  # Random condition
        'last_inspected': (datetime.now() - timedelta(days=random.randint(1, 30))).isoformat(),  # Last inspection date
        'traffic_level': random.choice(['Low', 'Medium', 'High']),  # Random traffic level
        'last_maintenance': (datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),  # Last maintenance date
        'geolocation': {
            'latitude': 40 + random.random() * 10,  # Random latitude
            'longitude': -100 - random.random() * 20  # Random longitude
        },
        'traffic_density': random.randint(0, 1000),  # Random traffic density
        'speed_limit': random.choice([25, 35, 45, 55, 65]),  # Random speed limit
        'upcoming_maintenance': (datetime.now() + timedelta(days=random.randint(1, 90))).isoformat(),  # Upcoming maintenance date
        'weather_condition': random.choice(['Sunny', 'Rainy', 'Cloudy', 'Snowy'])  # Random weather condition
    })

# Function to initialize the database
def init_db():
    db_path = "database.db"  # Path to the database file
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        # Create a table for storing user queries
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                image_url TEXT NOT NULL,
                description TEXT NOT NULL,
                location TEXT
            )
        """)
        conn.commit()  # Commit the changes to the database

# Call the function to initialize the database
init_db()

@app.before_request
def session_timeout():
    # Set the session to be permanent, meaning it will not expire when the user closes the browser
    session.permanent = True
    # Set the lifetime of the permanent session to 30 minutes
    app.permanent_session_lifetime = timedelta(minutes=30)

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Apply the decorator to all protected routes
@app.route('/')
@login_required
def index():
    if session.get('role') == 'admin':
        # Pass the current datetime as 'now'
        return render_template('index.html', roads=roads, user=session['user'], role=session['role'], now=datetime.now())
    return redirect(url_for('query_page'))

@app.route('/query')
@login_required
def query_page():
    try:
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, timestamp, image_url, description FROM queries")
            queries = cursor.fetchall()
        return render_template('query.html', queries=queries)
    except sqlite3.Error as e:
        return jsonify({'error': 'Database error: ' + str(e)}), 500

@app.route('/submit_query', methods=['POST'])
def submit_query():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401  # Return unauthorized error if not logged in
    if 'image' not in request.files or request.files['image'].filename == '':
        return jsonify({'error': 'No image uploaded'}), 400  # Return error if no image is uploaded
    
    try:
        file = request.files['image']  # Get the uploaded file
        description = request.form['description']  # Get the description from the form
        location = request.form.get('location', '')  # Get the location from the form (optional)
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')  # Get the current timestamp
        filename = f"{session['user']}_{timestamp}_{file.filename}"  # Create a unique filename
        file_path = os.path.join(UPLOAD_FOLDER, filename)  # Define the file path for saving
        
        print("Saving file to:", file_path)  # Debugging output
        file.save(file_path)  # Save the uploaded file
        
        image_url = f'/static/uploads/{filename}'  # URL for the uploaded image
        
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            # Insert the query into the database
            cursor.execute("""
                INSERT INTO queries (username, timestamp, image_url, description, location)
                VALUES (?, ?, ?, ?, ?)
            """, (session['user'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), image_url, description, location))
            conn.commit()  # Commit the changes to the database
        
        return jsonify({'message': 'Query submitted successfully', 'image_url': image_url})  # Return success message
    
    except Exception as e:
        print("Error:", str(e))  # Debugging output
        return jsonify({'error': str(e)}), 500  # Handle any other errors

@app.route('/get_queries')
def get_queries():
    limit = request.args.get('limit', 5, type=int)
    page = request.args.get('page', 1, type=int)
    offset = (page - 1) * limit
    
    try:
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            
            # Get total count
            cursor.execute("SELECT COUNT(*) FROM queries")
            total = cursor.fetchone()[0]
            
            # Get paginated results
            cursor.execute("SELECT username, timestamp, image_url, description, location FROM queries ORDER BY timestamp DESC LIMIT ? OFFSET ?", 
                          (limit, offset))
            queries = cursor.fetchall()
            
        # Return the queries as JSON with pagination info
        return jsonify({
            'queries': [{'username': q[0], 'timestamp': q[1], 'image_url': q[2], 'description': q[3], 'location': q[4] or 'Location not specified'} for q in queries],
            'total': total,
            'page': page,
            'limit': limit
        })
    except sqlite3.Error as e:
        return jsonify({'error': 'Database error: ' + str(e)}), 500

@app.route('/road_detail/<int:road_id>')
@login_required
def road_detail(road_id):
    road = next((r for r in roads if r['id'] == road_id), None)
    if road:
        return render_template('road_detail.html', road=road)
    return "Road not found", 404

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('index'))  # Redirect logged-in users to index if they try to access login
    
    if request.method == 'POST':
        username = request.form['username']  # Get the username from the form
        password = request.form['password']  # Get the password from the form
        user = next((u for u in users if u["username"] == username), None)  # Find the user by username
        if user and check_password_hash(user["password"], password):  # Check if the password is correct
            session['user'] = user['username']  # Store user in session
            session['role'] = user['role']  # Store user role in session
            return redirect(url_for('index'))  # Redirect to index page
        else:
            return render_template('login.html', error="Invalid credentials")  # Invalid login
    return render_template('login.html')  # Render login page

@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    
    # Instead of redirecting directly to login, redirect to a special logout page
    return redirect(url_for('perform_logout'))

@app.route('/perform_logout')
def perform_logout():
    # This page will handle the final redirect to login
    return render_template('logout.html')

# Add a session check endpoint
@app.route('/check_session')
def check_session():
    """Check if the user is logged in and return the status as JSON."""
    return jsonify({'logged_in': 'user' in session})

@app.after_request
def add_header(response):
    # Prevent caching for all responses
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    
    # Add additional headers to prevent caching
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    return response

if __name__ == '__main__':
    app.run(debug=True)  # Run the app in debug mode
