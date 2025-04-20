import os
from flask import Flask, render_template, redirect, url_for, session, flash
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard')
def dashboard():
    # Check if user is logged in
    if 'id_token' not in session:
        flash('Please log in to access the dashboard', 'warning')
        return redirect(url_for('auth.login'))
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
