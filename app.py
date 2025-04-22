# ============================================================================
# IMPORTS SECTION
# ============================================================================

# Flask: Main framework for web application
#   - Flask: The core class to create a Flask application instance
#   - render_template: Function to render HTML templates
#   - redirect: Function to redirect users to different routes
#   - url_for: Function to build URLs for routes dynamically
#   - session: Dictionary-like object to store data between requests
#   - flash: Function to send temporary messages to the next request
import logging
from flask import Flask, render_template

# os: Module for interacting with operating system
#   - Used here primarily for accessing environment variables
import os

# python-dotenv's load_dotenv: Loads environment variables from .env file
#   - Makes environment variables defined in .env available through os.getenv()
from dotenv import load_dotenv

# Importing the authentication blueprint from routes/auth.py
#   - Blueprint: A way to organize related routes in a modular way
#   - auth_bp: The blueprint instance containing all authentication routes
from routes.auth import auth_bp
from routes.account import account_bp
from routes.media import media_bp

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# ============================================================================
# CONFIGURATION SECTION
# ============================================================================

# Load all environment variables from .env file into the application
# This makes variables like APP_SECRET_KEY accessible via os.getenv()
load_dotenv()

# ============================================================================
# APPLICATION INITIALIZATION
# ============================================================================

# Create the Flask application instance
# __name__ is a special Python variable containing the name of the current module
# Flask uses this to know where to look for templates, static files, etc.
app = Flask(__name__)

# Set the secret key for the Flask application
# Secret key is used for:
#   - Securing sessions
#   - Generating CSRF tokens
#   - Flash messages
# IMPORTANT: Should be kept secret and not committed to version control
app.secret_key = os.getenv('APP_SECRET_KEY')

# ============================================================================
# BLUEPRINT REGISTRATION
# ============================================================================

# Register the authentication blueprint with a URL prefix
# - All routes defined in auth_bp will be prefixed with '/auth'
# - Example: @auth_bp.route('/login') becomes accessible at '/auth/login'
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(account_bp, url_prefix='/account')
app.register_blueprint(media_bp)

# ============================================================================
# ROUTE DEFINITIONS
# ============================================================================

# Define the home route (root URL '/')
# @app.route() is a decorator that tells Flask:
#   - What URL should trigger this function
#   - What HTTP methods are allowed (GET by default)
@app.route('/')
def home():
    # render_template() looks for home.html in the templates folder
    # and returns its contents to the user's browser
    return render_template('home.html')

# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

# This conditional ensures that the app only runs if this file is executed directly
# (not when it's imported as a module)
if __name__ == '__main__':
    # Start the development server
    # debug=True enables:
    #   - Interactive debugger
    #   - Auto-reload on code changes
    #   - More detailed error messages
    # WARNING: debug=True should never be used in production
    app.run(debug=True)

