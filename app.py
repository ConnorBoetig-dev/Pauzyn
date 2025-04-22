# ------------------- IMPORTS AND DEPENDENCIES ---------------------------
from flask import Flask, render_template
import os
from dotenv import load_dotenv
from routes.auth import auth_bp
from routes.account import account_bp
from routes.media import media_bp
from utils.db_manager import DynamoDBManager

# ------------------- ENVIRONMENT SETUP ---------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY')

# Create db_manager instance
app.db_manager = DynamoDBManager(region_name=os.getenv('AWS_REGION'))

# ------------------- BLUEPRINT REGISTRATION ---------------------------
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(account_bp, url_prefix='/account')
app.register_blueprint(media_bp)

# ------------------- MAIN ROUTES ---------------------------
@app.route('/')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True)                            # start dev server; auto‑reload & verbose errors

