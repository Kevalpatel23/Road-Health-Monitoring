# Import necessary libraries for the application
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from datetime import datetime, timedelta
import os
import sqlite3
import random
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from utils.inference import ModelInference  # Import the inference class
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

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
                location TEXT,
                status TEXT
            )
        """)
        
        
        conn.commit()  # Commit the changes to the database

# Call the function to initialize the database
init_db()

# Load the YOLO model
model_inference = ModelInference('/Users/harshit/Documents/Road-Health-Monitoring/static/model/detection_model.pt')  # Adjust the path to your .pt file

# Initialize rate limiter with more lenient limits for session checks
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Add a specific limit for session checks
session_limiter = limiter.shared_limit("30 per minute", scope="session")

@app.before_request
def session_timeout():
    # Set the session to be permanent, meaning it will not expire when the user closes the browser
    session.permanent = True
    # Set the lifetime of the permanent session to 30 minutes
    app.permanent_session_lifetime = timedelta(minutes=30)

@app.before_request
def log_request():
    print(f"Request: {request.method} {request.path}")

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
    
    file_path = None  # Initialize file_path variable
    try:
        file = request.files['image']  # Get the uploaded file
        description = request.form['description']  # Get the description from the form
        location = request.form.get('location', '')  # Get the location from the form (optional)
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')  # Get the current timestamp
        filename = f"{session['user']}_{timestamp}_{file.filename}"  # Create a unique filename
        file_path = os.path.join(UPLOAD_FOLDER, filename)  # Define the file path for saving
        
        print("Saving file to:", file_path)  # Debugging output
        file.save(file_path)  # Save the uploaded file
        
        # Run inference on the uploaded image
        pothole_detected = model_inference.predict(file_path)

        if pothole_detected:
            image_url = f'/static/uploads/{filename}'  # URL for the uploaded image
            
            with sqlite3.connect("database.db") as conn:
                cursor = conn.cursor()
                # Insert the query into the database with default status 'pending'
                cursor.execute("""
                    INSERT INTO queries (username, timestamp, image_url, description, location, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (session['user'], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), image_url, description, location, 'pending'))
                
                # Update road conditions based on pothole detection
                # Find the closest road to the reported location
                if location:
                    try:
                        lat, lng = map(float, location.split(','))
                        # Find the road with the closest geolocation
                        closest_road = min(roads, key=lambda r: 
                            ((r['geolocation']['latitude'] - lat) ** 2 + 
                             (r['geolocation']['longitude'] - lng) ** 2) ** 0.5)
                        
                        # Update the road's condition based on the detection
                        current_condition = closest_road['condition']
                        if current_condition == 'Good':
                            closest_road['condition'] = 'Fair'
                        elif current_condition == 'Fair':
                            closest_road['condition'] = 'Poor'
                        elif current_condition == 'Poor':
                            closest_road['condition'] = 'Critical'
                        
                        # Update last inspected date
                        closest_road['last_inspected'] = datetime.now().isoformat()
                        
                    except ValueError:
                        # If location parsing fails, just continue without updating road conditions
                        pass
                
                conn.commit()  # Commit the changes to the database
            
            return jsonify({
                'message': 'Query submitted successfully', 
                'image_url': image_url,
                'success': True,
                'road_updated': True if location else False
            })  # Return success message
        else:
            return jsonify({
                'message': 'No pothole detected. Image not saved.',
                'success': False
            }), 200  # Return message if no pothole detected
    
    except Exception as e:
        print("Error:", str(e))  # Debugging output
        if file_path and os.path.exists(file_path):
            os.remove(file_path)  # Remove the file if an error occurs
        return jsonify({'error': str(e)}), 500  # Handle any other errors

@app.route('/get_queries')
def get_queries():
    try:
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            
            # Get all queries ordered by timestamp, including id and status
            cursor.execute("""
                SELECT id, username, timestamp, image_url, description, location, status 
                FROM queries 
                ORDER BY timestamp DESC
            """)
            queries = cursor.fetchall()
            
            # Process queries to extract location coordinates
            processed_queries = []
            for q in queries:
                location = q[5] or 'Location not specified'
                lat, lng = None, None
                if location != 'Location not specified':
                    try:
                        lat, lng = map(float, location.split(','))
                    except ValueError:
                        pass
                processed_queries.append({
                    'id': q[0],
                    'username': q[1],
                    'timestamp': q[2],
                    'image_url': q[3],
                    'description': q[4],
                    'location': location,
                    'status': q[6],
                    'coordinates': {'lat': lat, 'lng': lng} if lat and lng else None
                })
        
        return jsonify({
            'queries': processed_queries,
            'total': len(processed_queries)
        })
    except sqlite3.Error as e:
        return jsonify({'error': 'Database error occurred'}), 500

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
@session_limiter
def check_session():
    """Check if the user is still logged in and return the status as JSON."""
    try:
        if 'user' in session:
            return jsonify({'logged_in': True})
        return jsonify({'logged_in': False})
    except Exception as e:
        app.logger.error(f"Error in check_session: {str(e)}")
        return jsonify({'logged_in': False})

@app.after_request
def add_header(response):
    # Prevent caching for all responses
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    
    # Add security headers
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Updated CSP to allow necessary resources
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.tailwindcss.com; "
        "img-src 'self' data: https://images.unsplash.com; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'"
    )
    
    return response

@app.route('/api/maintenance', methods=['POST'])
@login_required  # Ensure the user is logged in
def maintenance():
    data = request.get_json()  # Get the JSON data from the request
    road_id = data.get('road_id')  # Extract the road ID
    description = data.get('description')  # Extract the description

    # Get the current timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Insert the maintenance request into the database
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO maintenance_requests (road_id, description, timestamp)
            VALUES (?, ?, ?)
        """, (road_id, description, timestamp))
        conn.commit()  # Commit the changes to the database

    return jsonify({'message': 'Maintenance request submitted successfully for road ID: {}'.format(road_id)}), 200

@app.route('/update_complaint_status', methods=['POST'])
def update_complaint_status():
    data = request.get_json()
    complaint_id = data.get('complaint_id')
    new_status = data.get('status')
    if not complaint_id or not new_status:
        return jsonify({'error': 'Missing complaint_id or status'}), 400
    try:
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE queries SET status = ? WHERE id = ?
            """, (new_status, complaint_id))
            conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Admin routes with rate limiting and authentication
@app.route('/admin/dashboard')
@login_required
@limiter.limit("30 per minute")
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('index'))
    return render_template('admin_dashboard.html')

@app.route('/api/pothole_detections')
@login_required
@limiter.limit("30 per minute")
def get_pothole_detections():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, image_url, description, location, status 
                FROM queries 
                ORDER BY timestamp DESC
            """)
            detections = cursor.fetchall()
            
            processed_detections = []
            for d in detections:
                processed_detections.append({
                    'id': d[0],
                    'timestamp': d[1],
                    'image_url': d[2],
                    'description': d[3],
                    'location': d[4],
                    'status': d[5]
                })
            
            return jsonify({'detections': processed_detections})
    except sqlite3.Error:
        return jsonify({'error': 'Database error occurred'}), 500

# Error handler for rate limit exceeded
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'rate_limit_exceeded',
        'message': 'Too many requests. Please try again later.'
    }), 429

if __name__ == '__main__':
    app.run(debug=True)  # Run the app in debug mode
