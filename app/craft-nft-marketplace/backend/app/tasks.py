# craft-nft-marketplace/backend/app/tasks.py
from celery import Celery
from .email_service import send_nft_email
from .config import settings
import os

celery = Celery('tasks', broker=os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0'))
celery.config_from_object('celeryconfig')

@celery.task
def send_email_task(user_email: str, nft_svg: str, nft_id: str, transaction_hash: str):
    """Celery task to send email asynchronously."""
    print(f"Sending email task for {user_email}...")
    return send_nft_email(user_email, nft_svg, nft_id, transaction_hash)

@celery.task
def send_weekly_report():
    """Celery task to send weekly report (example)."""
    print('report time')
    # Logic to generate and send a weekly report
    # This is just a placeholder, you would need to implement the actual logic
    return 'Weekly report sent!'