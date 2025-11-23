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

    email = body["email"]
    password = body["password"]

    if not email or not password:
        return {"statusCode": 400, "body": "missing fields"}

    dynamo = boto3.resource('dynamodb')
    customers = dynamo.Table(os.getenv("CUSTOMERS_TABLE"))
    sessions = dynamo.Table(os.getenv("SESSIONS_TABLE"))

    old = sessions.scan(
        FilterExpression="email = :u AND isActive = :v",
        ExpressionAttributeValues={":u": email, ":v": True}
    ).get("Items", [])

    for s in old:
        sessions.update_item(
            Key={"session_id": s["session_id"]},
            UpdateExpression="set isActive = :f",
            ExpressionAttributeValues={":f": False}
        )


    # BUSCAMOS AL USUARIO DIRECTO POR Y user_id
    res = customers.get_item(Key={"email": email})

    if "Item" not in res:
        return {"statusCode": 404, "body": "customer not found"}

    customer = res["Item"]

    if not customer["isActive"]:
        return {"statusCode": 403, "body": "customer disabled"}

    # VALIDACIÓN DE PASSWORD
    if customer["password_hash"] != hash_password(password):
        return {"statusCode": 401, "body": "invalid credentials"}

    session_id = str(uuid.uuid4())

    # CREAMOS TOKEN
    payload = {
        "sub": customer["customer_id"],
        "session_id": session_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 43200,
    }

    token = make_token(payload)

    sessions.put_item(Item={
        "session_id": session_id,
        "email": customer["email"],
        "token": token,
        "created_at": int(time.time()),
        "expires_at": payload["exp"],
        "isActive": True
    })

    log_info = {
        "event": "login",
        "email": customer["email"],
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
