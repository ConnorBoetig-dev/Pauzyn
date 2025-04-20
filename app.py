# Importing necessary modules
import os
from flask import Flask, render_template, redirect, url_for, session, flash
from dotenv import load_dotenv
from routes.auth import auth_bp

# Load environment variables from .env file
load_dotenv()

# Initialize Flask application
app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY')

# Register the auth blueprint
app.register_blueprint(auth_bp, url_prefix='/auth')

@app.route('/')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True)

