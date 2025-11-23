import uuid, boto3, os, json, hashlib, hmac, base64, time

JWT_SECRET = os.getenv("JWT_SECRET")

def make_token(payload):
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(
        hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    return f"{header}.{body}.{signature}"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def lambda_handler(event, context):
    body = event.get("body")

    if isinstance(body, str):
        body = json.loads(body)

    staff_id = body["staff_id"]
    password = body["password"]

    if not staff_id or not password:
        return {"statusCode": 400, "body": "missing fields"}

    dynamo = boto3.resource('dynamodb')
    staff = dynamo.Table(os.getenv("STAFF_TABLE"))
    sessions = dynamo.Table(os.getenv("SESSIONS_TABLE"))

    old = sessions.scan(
        FilterExpression="staff_id = :u AND isActive = :v",
        ExpressionAttributeValues={":u": staff_id, ":v": True}
    ).get("Items", [])

    for s in old:
        sessions.update_item(
            Key={"session_id": s["session_id"]},
            UpdateExpression="set isActive = :f",
            ExpressionAttributeValues={":f": False}
        )

    res = staff.get_item(Key={"staff_id": staff_id})

    if "Item" not in res:
        return {"statusCode": 404, "body": "staff not found"}

    staff_member = res["Item"]
    if not staff_member["isActive"]:
        return {"statusCode": 403, "body": "staff disabled"}

    # VALIDACIÓN DE PASSWORD
    if staff_member["password_hashed"] != hash_password(password):
        return {"statusCode": 401, "body": "invalid credentials"}

    session_id = str(uuid.uuid4())

    # CREAMOS TOKEN
    payload = {
        "sub": staff_member["staff_id"],
        "session_id": session_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 43200,
    }

    token = make_token(payload)

    sessions.put_item(Item={
        "session_id": session_id,
        "staff_id": staff_member["staff_id"],
        "token": token,
        "created_at": int(time.time()),
        "expires_at": payload["exp"],
        "isActive": True
    })

    log_info = {
        "event": "login",
        "staff_id": staff_member["staff_id"],
        "session_id": session_id,
        "timestamp": int(time.time())
    }
    print("INFO:", json.dumps(log_info))

    return {
        "statusCode": 200,
        "body": json.dumps({
            "token": token,
            "session_id": session_id,
        })
    }
