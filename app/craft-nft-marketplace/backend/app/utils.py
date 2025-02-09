# craft-nft-marketplace/backend/app/utils.py
import base64
from solana.keypair import Keypair
from solana.publickey import PublicKey

def generate_keypair():
    """Generates a new Solana keypair."""
    keypair = Keypair()
    private_key_b64 = base64.b64encode(keypair.secret_key).decode('utf-8')
    public_key = str(keypair.pubkey())

    return public_key, private_key_b64

def validate_public_key(public_key: str) -> bool:
    """Validates if a string is a valid Solana public key."""
    try:
        PublicKey(public_key)
        return True
    except Exception:
        return False