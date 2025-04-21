from flask import Blueprint, jsonify, request, render_template, session, redirect, url_for
import boto3
from botocore.config import Config
from uuid import uuid4
from datetime import datetime
from functools import wraps
import jwt

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'id_token' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

# Configure S3 client with regional endpoint
s3_config = Config(
    region_name="us-east-2",
    signature_version="s3v4",
    s3={"addressing_style": "virtual"}  # Uses bucketname.s3.us-east-2.amazonaws.com
)

media_bp = Blueprint('media', __name__)
s3_client = boto3.client('s3', config=s3_config)

@media_bp.route('/upload')
@login_required
def upload_page():
    return render_template('media/upload.html')

# Your existing presigned URL route
@media_bp.route('/api/media/presigned-url', methods=['POST'])
@login_required
def get_presigned_url():
    file_name = request.json.get('fileName')
    file_type = request.json.get('fileType')
    
    if not file_name or not file_type:
        return jsonify({'error': 'Missing fileName or fileType'}), 400
        
    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    user_id = decoded_token.get('sub')
    
    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    unique_id = str(uuid4())[:8]
    file_key = f"users/{user_id}/{timestamp}-{unique_id}-{file_name}"
    
    try:
        presigned_url = s3_client.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': 'pauzynbucket',
                'Key': file_key,
                'ContentType': file_type  # Removed ACL parameter
            },
            ExpiresIn=300,
            HttpMethod='PUT'
        )
        
        return jsonify({
            'presignedUrl': presigned_url,
            'fileKey': file_key
        })
    except Exception as e:
        print(f"Error generating presigned URL: {str(e)}")
        return jsonify({'error': str(e)}), 500




