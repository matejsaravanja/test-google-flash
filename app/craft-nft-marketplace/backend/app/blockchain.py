# craft-nft-marketplace/backend/app/blockchain.py
from solana.rpc.api import Client
from solana.keypair import Keypair
from solana.publickey import PublicKey
from solana.transaction import Transaction
from spl.token.client import Token
from spl.token import instructions as spl_token_instructions
from spl.token.constants import TOKEN_PROGRAM_ID
from .config import settings
import base64


SOLANA_NETWORK = settings.SOLANA_NETWORK
CRAFT_MINT_ADDRESS = settings.CRAFT_MINT_ADDRESS
APPLICATION_WALLET_PRIVATE_KEY = settings.APPLICATION_WALLET_PRIVATE_KEY
TREASURY_WALLET_PUBLIC_KEY = settings.TREASURY_WALLET_PUBLIC_KEY
MARKETPLACE_FEE = settings.MARKETPLACE_FEE

def transfer_tokens(client, sender_keypair, receiver_pubkey, mint_pubkey, amount):
    """Helper function to transfer tokens."""
    sender_ata = Token.get_associated_token_address(
        sender_keypair.pubkey(),
        mint_pubkey,
    )
    receiver_ata = Token.get_associated_token_address(
        receiver_pubkey,
        mint_pubkey,
    )

    transfer_ix = spl_token_instructions.transfer(
        spl_token_instructions.TransferParams(
            TOKEN_PROGRAM_ID,
            sender_ata,
            receiver_ata,
            sender_keypair.pubkey(),
            int(amount),
            [sender_keypair]
        )
    )

    return transfer_ix

def mint_nft_transaction(receiver_public_key: str):
    """
    Mints a new NFT (represented as CRAFT tokens) and transfers it to the receiver.
    This creates and returns the full transaction, ready for signing and sending.
    """
    try:
        client = Client(SOLANA_NETWORK)
        app_keypair = Keypair.from_secret_key(base64.b64decode(APPLICATION_WALLET_PRIVATE_KEY))
        receiver_pubkey = PublicKey(receiver_public_key)
        craft_mint_pubkey = PublicKey(CRAFT_MINT_ADDRESS)
        treasury_pubkey = PublicKey(TREASURY_WALLET_PUBLIC_KEY)

        #Example NFT Price
        nft_price = 10  # 10 CRAFT tokens
        marketplace_fee_amount = int(nft_price * MARKETPLACE_FEE) #Amount taken as fee
        seller_amount = int(nft_price - marketplace_fee_amount) #Amount to Seller

        # 1. Transfer portion to Seller
        transfer_to_seller_ix = transfer_tokens(client, app_keypair, receiver_pubkey, craft_mint_pubkey, seller_amount)

        # 2. Transfer Marketplace Fee to Treasury
        transfer_to_treasury_ix = transfer_tokens(client, app_keypair, treasury_pubkey, craft_mint_pubkey, marketplace_fee_amount)


        # Create the transaction
        transaction = Transaction().add(transfer_to_seller_ix, transfer_to_treasury_ix)
        transaction.fee_payer = app_keypair.pubkey()
        recent_blockhash = client.get_latest_blockhash().value.blockhash
        transaction.recent_blockhash = recent_blockhash

        #Sign as payer
        transaction.sign(app_keypair)


        #Sanity Check for validity (remove in prod, slows things down a bit)
        #transaction.verify()
        return transaction

    except Exception as e:
        print(f"Error creating mint NFT transaction: {e}")
        return None

def send_and_confirm_transaction(transaction):
    """Sends and confirms a Solana transaction."""
    try:
        client = Client(SOLANA_NETWORK)
        result = client.send_transaction(transaction)
        return result['result']

    except Exception as e:
        print(f"Error sending transaction: {e}")
        return None

def check_transaction_status(signature: str):
    """Checks the status of a Solana transaction."""
    try:
        client = Client(SOLANA_NETWORK)
        result = client.get_signature_statuses([signature])

        if result and result['result'] and result['result'][0]:
            confirmation_status = result['result'][0]['confirmationStatus']
            return confirmation_status == 'confirmed' or confirmation_status == 'finalized'
        else:
            return False
    except Exception as e:
        print(f"Error checking transaction status: {e}")
        return False