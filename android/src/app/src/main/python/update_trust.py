"""Verify remote data with Android crypto, or cryptography in source tools."""
import base64
import json
import pkgutil
import time

def verified_text(text):
    return verified_payload(text.encode('utf-8')).decode('utf-8')


def verified_payload(data,now=None):
    if len(data)>65536:raise ValueError('Signed data too large')
    try:
        from java import jclass
    except ImportError:
        return _host_payload(data,time.time() if now is None else now)
    try:
        result = jclass('dev.graybridge.UpdateTrust').payload(data.decode('utf-8'))
        return str(result).encode('utf-8')
    except Exception as error:
        raise ValueError('DNS catalog signature cannot be verified') from error


def _host_payload(data,now):
    try:
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        trust=json.loads(pkgutil.get_data(__name__,'update_trust.json'))
        value=json.loads(data)
        assert value['keyId']==trust['key_id']
        signed_at,expires=value['signedAt'],value['expires']
        assert type(signed_at) is int and type(expires) is int
        assert signed_at<=now+300 and now<expires and 0<expires-signed_at<=366*86400
        key=serialization.load_der_public_key(base64.b64decode(trust['public_key'],validate=True))
        assert isinstance(key,ec.EllipticCurvePublicKey) and isinstance(key.curve,ec.SECP256R1)
        message=f"SorryRKN-Envelope-v1\n{value['keyId']}\n{signed_at}\n{expires}\n{value['signed']}".encode()
        key.verify(base64.b64decode(value['signature'],validate=True),message,ec.ECDSA(hashes.SHA256()))
        payload=base64.b64decode(value['signed'],validate=True)
        assert isinstance(json.loads(payload),dict)
        return payload
    except Exception as error:
        raise ValueError('Update signature is invalid or expired') from error
