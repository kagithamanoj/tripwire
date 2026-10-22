"""AWS-backed receipt signing (KMS) and storage (DynamoDB). boto3 is imported lazily."""

import json
import time

ALG = "ECDSA_SHA_256"


def _client(name: str):
    import boto3

    return boto3.client(name)


class KmsSigner:
    """Signs receipt digests with an asymmetric KMS key. The private key never leaves KMS."""

    def __init__(self, key_id: str, client=None):
        self.key_id = key_id
        self.client = client or _client("kms")

    def sign(self, digest_hex: str) -> str:
        r = self.client.sign(KeyId=self.key_id, Message=bytes.fromhex(digest_hex),
                             MessageType="DIGEST", SigningAlgorithm=ALG)
        return r["Signature"].hex()

    def check(self, digest_hex: str, sig_hex: str) -> bool:
        try:
            r = self.client.verify(KeyId=self.key_id, Message=bytes.fromhex(digest_hex),
                                   MessageType="DIGEST", SigningAlgorithm=ALG,
                                   Signature=bytes.fromhex(sig_hex))
            return bool(r["SignatureValid"])
        except Exception as e:  # botocore ClientError for a bad signature; anything else is a real error
            code = getattr(e, "response", {}).get("Error", {}).get("Code")
            if code == "KMSInvalidSignatureException":
                return False
            raise


class DynamoSink:
    """Persists each receipt. Table key: session_id (S) + seq (N); `ttl` attribute enables expiry."""

    def __init__(self, table: str, client=None, ttl_days: int = 90):
        self.table = table
        self.client = client or _client("dynamodb")
        self.ttl_s = ttl_days * 86400

    def __call__(self, session_id: str, receipt: dict) -> None:
        self.client.put_item(TableName=self.table, Item={
            "session_id": {"S": session_id},
            "seq": {"N": str(receipt["seq"])},
            "receipt": {"S": json.dumps(receipt, sort_keys=True)},
            "ttl": {"N": str(int(time.time()) + self.ttl_s)},
        })

    def load(self, session_id: str) -> list[dict]:
        r = self.client.query(
            TableName=self.table, KeyConditionExpression="session_id = :s",
            ExpressionAttributeValues={":s": {"S": session_id}}, ConsistentRead=True)
        return [json.loads(i["receipt"]["S"]) for i in r.get("Items", [])]


class DynamoReviewStore:
    """Pending/decided human-review items. Table key: id (S); `ttl` lets DynamoDB clean up old items."""

    def __init__(self, table: str, client=None, ttl_days: int = 7):
        self.table = table
        self.client = client or _client("dynamodb")
        self.ttl_s = ttl_days * 86400

    def put(self, item: dict) -> None:
        self.client.put_item(TableName=self.table, Item={
            "id": {"S": item["id"]},
            "status": {"S": item["status"]},
            "item": {"S": json.dumps(item, sort_keys=True)},
            "ttl": {"N": str(int(time.time()) + self.ttl_s)},
        })

    def get(self, rid: str) -> dict | None:
        r = self.client.get_item(TableName=self.table, Key={"id": {"S": rid}}, ConsistentRead=True)
        return json.loads(r["Item"]["item"]["S"]) if "Item" in r else None

    def pending(self) -> list[dict]:
        """Table scan: fine for a demo-sized queue; use a status GSI at scale."""
        out, kw = [], {}
        while True:
            r = self.client.scan(TableName=self.table, FilterExpression="#s = :p",
                                 ExpressionAttributeNames={"#s": "status"},
                                 ExpressionAttributeValues={":p": {"S": "pending"}}, **kw)
            out += [json.loads(i["item"]["S"]) for i in r.get("Items", [])]
            if "LastEvaluatedKey" not in r:
                return out
            kw = {"ExclusiveStartKey": r["LastEvaluatedKey"]}


def get_secret(arn: str, client=None) -> str:
    c = client or _client("secretsmanager")
    return c.get_secret_value(SecretId=arn)["SecretString"]
