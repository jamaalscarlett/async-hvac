import hmac
from datetime import datetime
from hashlib import sha256


class SigV4Auth(object):
    def __init__(self, access_key, secret_key, session_token=None):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token

    def add_auth(self, method, headers, body):
        if body:
            headers["Content-Length"] = str(len(body))
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        headers["X-Amz-Date"] = timestamp

        if self.session_token:
            headers["X-Amz-Security-Token"] = self.session_token

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        canonical_headers = "".join(
            "{0}:{1}\n".format(k.lower(), headers[k]) for k in sorted(headers)
        )
        signed_headers = ";".join(k.lower() for k in sorted(headers))
        payload_hash = sha256(body.encode("utf-8")).hexdigest()
        canonical_request = "\n".join(
            [method, "/", "", canonical_headers, signed_headers, payload_hash]
        )

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = "/".join(
            [timestamp[0:8], "us-east-1", "sts", "aws4_request"]
        )
        canonical_request_hash = sha256(canonical_request.encode("utf-8")).hexdigest()
        string_to_sign = "\n".join(
            [algorithm, timestamp, credential_scope, canonical_request_hash]
        )

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
        key = "AWS4{0}".format(self.secret_key).encode("utf-8")
        key = hmac.new(key, timestamp[0:8].encode("utf-8"), sha256).digest()
        key = hmac.new(key, "us-east-1".encode("utf-8"), sha256).digest()
        key = hmac.new(key, "sts".encode("utf-8"), sha256).digest()
        key = hmac.new(key, "aws4_request".encode("utf-8"), sha256).digest()
        signature = hmac.new(key, string_to_sign.encode("utf-8"), sha256).hexdigest()

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
        authorization = (
            "{0} Credential={1}/{2}, SignedHeaders={3}, Signature={4}".format(
                algorithm, self.access_key, credential_scope, signed_headers, signature
            )
        )
        headers["Authorization"] = authorization
