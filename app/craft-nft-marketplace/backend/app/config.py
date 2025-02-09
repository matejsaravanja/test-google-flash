# craft-nft-marketplace/backend/app/config.py
import os

class Settings:
    SOLANA_NETWORK = os.getenv("SOLANA_NETWORK", "http://127.0.0.1:8899")  # Change this to devnet/mainnet-beta appropriately
    CRAFT_MINT_ADDRESS = os.getenv("CRAFT_MINT_ADDRESS", "YOUR_CRAFT_MINT_ADDRESS")
    APPLICATION_WALLET_PRIVATE_KEY = os.getenv("APPLICATION_WALLET_PRIVATE_KEY", "YOUR_APPLICATION_WALLET_PRIVATE_KEY")
    TREASURY_WALLET_PUBLIC_KEY = os.getenv("TREASURY_WALLET_PUBLIC_KEY", "YOUR_TREASURY_WALLET_PUBLIC_KEY") #For collecting fees and revenue
    EMAIL_HOST = os.getenv("EMAIL_HOST")
    EMAIL_PORT = os.getenv("EMAIL_PORT", 587)
    EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
    EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
    EMAIL_FROM_ADDRESS = os.getenv("EMAIL_FROM_ADDRESS")
    MARKETPLACE_FEE = float(os.getenv("MARKETPLACE_FEE", 0.02)) # 2% Marketplace Fee

settings = Settings()