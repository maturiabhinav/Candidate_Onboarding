import jwt
import boto3
import uuid
import os
from datetime import datetime, timezone, timedelta
from flask import current_app, url_for
from flask_mail import Message
from candidate_onboarding import mail
from botocore.exceptions import ClientError

# ==================== EMAIL UTILITIES ====================

def send_email(subject, recipient, template):
    try:
        msg = Message(
            subject,
            recipients=[recipient],
            html=template,
            sender=current_app.config.get('MAIL_DEFAULT_SENDER') or current_app.config.get('MAIL_USERNAME')
        )
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def generate_token(user_id, token_type='reset'):
    payload = {
        'user_id': user_id,
        'token_type': token_type,
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token, token_type='reset'):
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        if payload['token_type'] != token_type:
            return None
        return payload['user_id']
    except:
        return None

# ==================== AWS S3 UTILITIES ====================

def get_s3_client():
    return boto3.client(
        's3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_REGION', 'us-east-1')
    )

def upload_to_s3(file, folder_name, employee_id):
    s3_client = get_s3_client()
    bucket_name = os.getenv('AWS_S3_BUCKET')
    
    # Generate unique filename
    file_extension = file.filename.rsplit('.', 1)[1].lower()
    unique_filename = f"{uuid.uuid4()}.{file_extension}"
    s3_key = f"{folder_name}/employee_{employee_id}/{unique_filename}"
    
    try:
        s3_client.upload_fileobj(
            file,
            bucket_name,
            s3_key,
            ExtraArgs={
                'ContentType': file.content_type,
                'ACL': 'private'
            }
        )
        
        # Generate presigned URL for download
        download_url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': s3_key},
        )
        
        return {
            's3_key': s3_key,
            'download_url': download_url,
            'file_url': f"s3://{bucket_name}/{s3_key}"
        }
    except ClientError as e:
        print(f"S3 upload error: {e}")
        return None