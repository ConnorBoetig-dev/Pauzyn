# ------------------- IMPORTS AND DEPENDENCIES ---------------------------
from flask import Blueprint, jsonify, request, render_template, session, redirect, url_for  # Flask primitives & helpers
import boto3                                                                             # AWS SDK for Python
from botocore.config import Config                                                      # Fine‑tune boto3 client
from uuid import uuid4                                                                   # Generate unique IDs
from datetime import datetime                                                             # Timestamps
from functools import wraps                                                               # Decorator helper
import jwt                                                                               # Decode Cognito JWTs
from flask import current_app                                                             # Access app context (db_manager)
import json                                                                              # Handle JSON for pagination keys

# ------------------- AUTHENTICATION DECORATOR ---------------------------

def login_required(f):                                                                   # restrict routes to logged‑in users
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'id_token' not in session:                                                   # no session token → not logged in
            return redirect(url_for('auth.login'))                                       # send user to login page
        return f(*args, **kwargs)                                                        # else proceed
    return decorated_function

# ------------------- AWS S3 CONFIGURATION ---------------------------

s3_config = Config(                                                                      # boto3 config w/ region & style
    region_name="us-east-2",                                                            # bucket lives in Ohio
    signature_version="s3v4",                                                           # presigned‑URL signature algo
    s3={"addressing_style": "virtual"}                                               # bucketname.s3.us‑east‑2.amazonaws.com
)

# ------------------- BLUEPRINT SETUP ---------------------------

media_bp = Blueprint('media', __name__)                                                  # /media blueprint
s3_client = boto3.client('s3', config=s3_config)                                         # S3 client instance

# ------------------- MEDIA UPLOAD INTERFACE ---------------------------

@media_bp.route('/upload')                                                               # GET /media/upload
@login_required
def upload_page():
    return render_template('media/upload.html')                                          # render drag‑and‑drop UI

# ------------------- S3 PRESIGNED URL GENERATION ---------------------------

@media_bp.route('/api/media/presigned-url', methods=['POST'])                            # POST JSON → presigned URL
@login_required
def get_presigned_url():
    file_name = request.json.get('fileName')                                             # original filename
    file_type = request.json.get('fileType')                                             # MIME type

    if not file_name or not file_type:                                                   # validate payload
        return jsonify({'error': 'Missing fileName or fileType'}), 400

    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})  # get user info
    user_id = decoded_token.get('sub')                                                   # Cognito user UUID

    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')                              # YYYYMMDD‑HHMMSS
    unique_id = str(uuid4())[:8]                                                         # short random ID
    file_key = f"users/{user_id}/{timestamp}-{unique_id}-{file_name}"                   # S3 object key

    try:
        presigned_url = s3_client.generate_presigned_url(                                # make PUT URL
            'put_object',
            Params={
                'Bucket': 'pauzynbucket',                                                # target bucket
                'Key': file_key,                                                         # object key
                'ContentType': file_type                                                 # enforce MIME type
            },
            ExpiresIn=300,                                                               # 5‑minute expiry
            HttpMethod='PUT'
        )

        # Record pending upload in DynamoDB
        media_id = current_app.db_manager.record_media_upload(                           # log "pending" item
            user_id=user_id,
            file_name=file_name,
            file_type=file_type,
            s3_location=file_key
        )

        if not media_id:                                                                 # write failed
            raise Exception("Failed to record media upload")

        return jsonify({
            'presignedUrl': presigned_url,
            'fileKey': file_key,
            'mediaId': media_id
        })                                                                                # success payload
    except Exception as e:
        print(f"Error generating presigned URL: {str(e)}")                              # quick console log
        return jsonify({'error': str(e)}), 500                                           # generic 500

# ------------------- S3 UPLOAD COMPLETE CALLBACK ---------------------------

@media_bp.route('/api/media/upload-complete', methods=['POST'])                          # POST after PUT succeeds
@login_required
def upload_complete():
    media_id  = request.json.get('mediaId')                                              # DynamoDB media item key
    file_size = request.json.get('fileSize')                                             # bytes uploaded

    if not media_id or not file_size:
        return jsonify({'error': 'Missing mediaId or fileSize'}), 400

    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    user_id = decoded_token.get('sub')

    # Update media status → "uploaded"
    success = current_app.db_manager.update_media_processing_status(
        user_id=user_id,
        media_id=media_id,
        status='uploaded',
        metadata={'file_size': file_size}
    )

    # Update monthly usage row
    usage_updated = current_app.db_manager.update_usage_stats(
        user_id=user_id,
        file_size=file_size,
        operation='upload'
    )

    if success and usage_updated:                                                        # both writes OK
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to update media status or usage'}), 500

# ------------------- PAGINATED MEDIA LIST ENDPOINT ---------------------------

@media_bp.route('/api/media/list', methods=['GET'])                                      # GET list w/ ?limit=&lastKey=
@login_required
def list_media():
    limit    = int(request.args.get('limit', 50))                                        # page size (default 50)
    last_key = request.args.get('lastKey')                                               # JSON string of last key

    decoded_token = jwt.decode(session['id_token'], options={"verify_signature": False})
    user_id = decoded_token.get('sub')

    if last_key:
        try:
            last_key = json.loads(last_key)                                             # str → dict for DynamoDB
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid lastKey format'}), 400

    result = current_app.db_manager.get_user_media(                                     # query DynamoDB
        user_id=user_id,
        limit=limit,
        last_evaluated_key=last_key
    )

    response = {
        'items': result['items'],                                                       # list of media items
        'hasMore': 'last_evaluated_key' in result                                        # pagination flag
    }

    if 'last_evaluated_key' in result:
        response['lastKey'] = json.dumps(result['last_evaluated_key'])                  # encode for query param

    return jsonify(response)                                                             # JSON payload to client
