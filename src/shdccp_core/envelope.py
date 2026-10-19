"""Transport envelope utilities. HMAC is for the localhost dev harness ONLY.
Production must use device identities, signatures, mTLS, anti-replay persistence.
The Einstein Tile's South Halo byte is not a security property.
"""
import json, hashlib, hmac

def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def digest_hex(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()

def sign_dev_hmac(value, key):
    if 'dev_mac' in value: raise ValueError('sign without dev_mac')
    return hmac.new(key, canonical_bytes(value), hashlib.sha256).hexdigest()

def verify_dev_hmac(value, key):
    d=dict(value)
    actual=d.pop('dev_mac',None)
    return isinstance(actual,str) and hmac.compare_digest(actual,sign_dev_hmac(d,key))

def validate_tile_hex(word):
    from .tile import unpack
    if not isinstance(word,str) or len(word)!=16:
        raise ValueError('tile_hex must be exactly 16 hexadecimal characters')
    raw=bytes.fromhex(word)
    return unpack(raw)
