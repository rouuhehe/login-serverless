import hashlib
import json, uuid, boto3, os
from time import time
from botocore.exceptions import ClientError
    
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def lambda_handler(event, context):
    try:
        if "body" in event:
            body = json.loads(event["body"]) if isinstance(event["body"], str) else event["body"]
        else:
            body = event  

        table_name = os.environ["ADMINS_TABLE"]
        if 'admin_code' not in body or body['admin_code'] != os.environ.get('ADMIN_REGISTRATION_CODE'):
            return {
                'statusCode': 403,
                'body': 'invalid admin_code'
            }
        
        admin_id = str(uuid.uuid4())
        now = str(int(time()))

        admin_data = {
            "admin_id": admin_id,
            "name": body['name'].lower(),
            "email": body['email'].lower(),
            "createdAt": now,
            "updatedAt": now,
            "isActive": True,
            "password_hashed": hash_password(body['password']),
            "phoneNumber": str(body['phone_number'])
        }

        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(table_name)
        table.put_item(Item=admin_data)

        return_data = {k: v for k, v in admin_data.items() if k != 'password_hashed'}

        return {
            'statusCode': 200,
            'body': {
                'admin': json.dumps(return_data)
                }
        }
    
    except ClientError as e:
        return {
            'statusCode': 500,
            'body': str(e)
        }
    except Exception as e:
        return {
            'statusCode': 400,
            'body': str(e)
        }