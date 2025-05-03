# Road Health Monitor 🚧

A smart pothole detection and reporting system that uses AI to identify road damage and streamline maintenance workflows.

![App Screenshot](https://images.unsplash.com/photo-1516822264827-4c33dd76f1ae)

## Features ✨

- **AI-Powered Detection**: YOLO model for accurate pothole identification
- **Real-time Reporting**: Instant submission with photo evidence
- **User Management**: Secure authentication with OTP verification
- **Dashboard Analytics**: Visualize complaint trends and status
- **Dark Mode**: Eye-friendly interface for all lighting conditions
- **Responsive Design**: Works on desktop and mobile devices

## Tech Stack 💻

- **Backend**: Python Flask
- **Frontend**: HTML5, Tailwind CSS, JavaScript
- **AI Model**: Ultralytics YOLO
- **Database**: SQLite
- **Email**: Flask-Mail for OTP

## Installation ⚙️

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/road-health-monitor.git
   cd road-health-monitor
   ```

2. **Set up environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate    # Windows
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**:
   Create a `.env` file:
   ```env
   SECRET_KEY=your_secret_key_here
   MAIL_SERVER=smtp.example.com
   MAIL_PORT=587
   MAIL_USERNAME=your_email@example.com
   MAIL_PASSWORD=your_email_password
   ```

5. **Initialize database**:
   ```bash
   python init_db.py
   ```

## Usage 🚀

1. **Run the application**:
   ```bash
   python app.py
   ```

2. **Access the web interface**:
   ```
   http://localhost:5000
   ```

3. **Default accounts**:
   - Admin: `admin/admin123`
   - User: `user/user123`

## Project Structure 📂

```
road-health-monitor/
├── app.py # Main application
├── requirements.txt # Python dependencies
├── static/
│ ├── model/ # AI model files
│ └── uploads/ # User-uploaded images
├── templates/ # HTML templates
├── utils/
│ └── inference.py # Model inference logic
└── database.db # SQLite database
```

## Additional Notes
- Ensure the `static/uploads/` directory exists for file uploads.
- The `app.secret_key` should be changed for production security.
- To stop the virtual environment, use `deactivate`.

## License
This project is open-source and can be modified as needed.

## API Endpoints 🌐

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home/Landing page |
| `/login` | GET/POST | User authentication |
| `/signup` | GET/POST | User registration |
| `/submit_query` | POST | Submit new pothole report |
| `/get_queries` | GET | Fetch all reports |
| `/update_complaint_status` | POST | Update report status |

## Contributing 🤝

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License 📜

MIT License - see [LICENSE](LICENSE) for details

## Screenshots 📸

![Dashboard](screenshots/dashboard.png)
![Mobile View](screenshots/mobile-view.png)

## Future Enhancements 🔮

- [ ] GPS integration for automatic location tagging
- [ ] Municipal API integration
- [ ] Severity classification system
- [ ] Push notifications

