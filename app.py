# ------------------- IMPORTS AND DEPENDENCIES ---------------------------
# Core Flask imports and utilities needed for the application setup,
# including logging, environment variables, and route blueprints

import logging                                     # std‑lib logging for debug/info output
from flask import Flask, render_template           # Flask core + helper to render HTML templates
import os                                          # access to operating‑system vars & paths
from dotenv import load_dotenv                     # reads .env file into the runtime environment

from routes.auth import auth_bp                    # auth Blueprint: login / signup routes
from routes.account import account_bp              # account Blueprint: profile / settings routes
from routes.media import media_bp                  # media Blueprint: upload / gallery routes

# ------------------- LOGGING CONFIGURATION ---------------------------
# Sets up application-wide logging with timestamps and debug level
# to help with development and troubleshooting

logging.basicConfig(                               # configure global logger once for the app
    level=logging.DEBUG,                           # show DEBUG and above (DEBUG, INFO, WARNING…)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'  # include timestamp + level
)

# ------------------- ENVIRONMENT SETUP ---------------------------
# Loads environment variables and configures core Flask settings
# including security keys and session management

load_dotenv()                                      # make variables in .env available via os.getenv

app = Flask(__name__)                              # create the Flask application object

app.secret_key = os.getenv('APP_SECRET_KEY')       # key that signs session cookies & CSRF tokens

# ------------------- BLUEPRINT REGISTRATION ---------------------------
# Registers different parts of the application (auth, account, media)
# with their respective URL prefixes for proper routing

app.register_blueprint(auth_bp, url_prefix='/auth')      # routes like /auth/login
app.register_blueprint(account_bp, url_prefix='/account') # routes like /account/profile
app.register_blueprint(media_bp)                          # routes defined exactly as written

# ------------------- MAIN ROUTES ---------------------------
# Core application routes that aren't part of any blueprint
# Currently just includes the home page

@app.route('/')                                    # map HTTP GET "/" to the function below
def home():                                        # controller for the homepage
    return render_template('home.html')            # render templates/home.html and return HTML

# ------------------- APPLICATION ENTRY POINT ---------------------------
# Starts the Flask development server when running this file directly
# with debugging enabled for development

if __name__ == '__main__':                         # run only if file executed directly (not imported)
    app.run(debug=True)                            # start dev server; auto‑reload & verbose errors

