# craft-nft-marketplace/backend/app/api.py
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from . import security
from .blockchain import mint_nft_transaction, send_and_confirm_transaction
from .nft_generator import generate_unique_nft
from .email_service import send_nft_email
from pydantic import BaseModel
from fastapi import BackgroundTasks
import secrets
from .utils import generate_keypair, validate_public_key

app = FastAPI()

origins = [
    "http://localhost:3000", # React default
    "http://localhost",
    "http://127.0.0.1:8000", #FastAPI may run on this one
    "http://127.0.0.1",
     # Add other origins allowed to access your API
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Data Models ---
class User(BaseModel):
    username: str
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class NFTMintRequest(BaseModel):
    receiver_public_key: str

class WalletCreationResponse(BaseModel):
    public_key: str
    private_key: str

# --- Utility Functions ---
def generate_strong_password() -> str:
    """Generates a cryptographically secure random password."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    password = ''.join(secrets.choice(alphabet) for i in range(12)) #12 characters good enough for demo
    return password

# --- API Endpoints ---
@app.get("/")
async def read_root():
    return {"message": "CRAFT NFT Marketplace API"}

@app.post("/register")
async def register_user(user: User):
    # In a real implementation, add user to a database
    hashed_password = security.hash_password(user.password)
    return {"message": "User registration implemented"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    tempPass = generate_strong_password()
    access_token = security.create_access_token(
        data={"sub": form_data.username , "password": tempPass} #generate a strong password for demo
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    user = security.verify_token(token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

@app.post("/create_wallet", response_model=WalletCreationResponse)
async def create_wallet(token: str = Depends(oauth2_scheme)):
    user = security.verify_token(token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    public_key, private_key = generate_keypair()
    return {"public_key": public_key, "private_key": private_key}


@app.post("/mint_nft")
async def mint_nft(request: NFTMintRequest, background_tasks: BackgroundTasks, token: str = Depends(oauth2_scheme)):
    """Mints a new NFT.
    Args:
        request: The mint request containing the receiver's public key.
        background_tasks: FastAPI background task manager
        token: JWT token to verify user
    Returns:
        The transaction hash and NFT ID.
    """
    user = security.verify_token(token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not validate_public_key(request.receiver_public_key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid public key forma Backend (FastAPI): `ct",
        )
    # 1. Create Mint NFT transaction
    try:
        transaction = mint_nft_transaction(request.receiver_public_key)
        if not transaction:
            raise HTTPException(status_code=500, detail="Failed to create transaction")

        # 2. Send and confirm transaction
        signature = send_and_confirm_transaction(transaction)
        if not signature:
            raise HTTPException(status_code=500, detail="Transaction failed to send/confirm")

        # 3. Generate Unique NFT
        nft_svg = generate_unique_nft(signature)

        # 4. Send NFT via email
        background_tasks.add_task(send_nft_email, user['sub'], nft_svg, signature, signature) #User sub is user email!

        # 5. Return the NFT details
        return {"transaction_hash": signature, "nft_svg": nft_svg}

    except Exception as e:
        print(f"Minting error: {e}") #Good to see backend print in console!
        raise HTTPException(status_code=500, detail=str(e))