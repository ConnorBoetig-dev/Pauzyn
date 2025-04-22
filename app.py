# ------------------- IMPORTS AND DEPENDENCIES ---------------------------
from flask import Flask, render_template       # core Flask class & Jinja template helper
import os                                      # stdlib for environment variables & paths
from dotenv import load_dotenv                 # loads .env files into os.environ
from routes.auth import auth_bp                # auth blueprint (login, signup, etc.)
from routes.account import account_bp          # account settings blueprint
from routes.media import media_bp              # media upload / gallery blueprint
from utils.db_manager import DynamoDBManager   # thin wrapper around boto3 for DynamoDB

# ------------------- ENVIRONMENT SETUP ---------------------------
load_dotenv()                                  # read .env file and populate os.environ

app = Flask(__name__)                          # create the Flask application object
app.secret_key = os.getenv('APP_SECRET_KEY')   # session encryption key (kept in .env)

# Create db_manager instance
app.db_manager = DynamoDBManager(              # attach DB wrapper to app for easy access
    region_name=os.getenv('AWS_REGION')        # AWS region where DynamoDB tables live
)

# ------------------- BLUEPRINT REGISTRATION ---------------------------
app.register_blueprint(auth_bp, url_prefix='/auth')       # mount /auth/* routes
app.register_blueprint(account_bp, url_prefix='/account') # mount /account/* routes
app.register_blueprint(media_bp)                          # mount /media/* routes (no prefix)

# ------------------- MAIN ROUTES ---------------------------
@app.route('/')                                 # map URL path "/" to view function below
def home():
    return render_template('home.html')         # render templates/home.html

if __name__ == '__main__':                      # only run when executed directly
    app.run(debug=True)                         # start dev server; auto‑reload & verbose errors
