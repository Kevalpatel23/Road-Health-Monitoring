# Flask Road Monitoring System

This is a Flask-based web application for monitoring road conditions, submitting queries with images, and user authentication.

## Prerequisites

Ensure you have the following installed on your system:
- Python 3.7+
- pip (Python package manager)

## Setup Instructions

### 1. Clone the Repository
```sh
$ git clone https://github.com/Kevalpatel23/Road-Health-Monitoring
$ cd Road-Health-Monitoring
```

### 2. Create a Virtual Environment (Optional)
```sh
$ python -m venv venv
$ source venv/bin/activate  # On macOS/Linux
$ venv\Scripts\activate    # On Windows
```

### 3. Install Dependencies
```sh
$ pip install -r requirements.txt
```

### 4. Initialize the Database
```sh
$ python
>>> from app import init_db
>>> init_db()
>>> exit()
```

### 5. Run the Flask Application
```sh
$ python app.py
```

The application will run on:
```
http://127.0.0.1:5000/
```

## Usage
- **Login:** Navigate to `/login` to log in using the provided credentials.
- **Admin Dashboard:** Admin users can monitor road conditions.
- **Submit Query:** Users can submit queries with images and descriptions.
- **View Queries:** Queries submitted by users can be viewed by administrators.

## Default Credentials
- **Admin**
  - Username: `admin`
  - Password: `admin123`
- **User**
  - Username: `user`
  - Password: `user123`

## Project Structure
```
/
│── app.py               # Main Flask application
│── database.db          # SQLite database
│── requirements.txt     # Required dependencies
│── static/uploads/      # Directory for uploaded images
│── templates/           # HTML templates
```

## Additional Notes
- Ensure the `static/uploads/` directory exists for file uploads.
- The `app.secret_key` should be changed for production security.
- To stop the virtual environment, use `deactivate`.

## License
This project is open-source and can be modified as needed.

