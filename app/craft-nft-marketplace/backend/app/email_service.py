# craft-nft-marketplace/backend/app/email_service.py
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from .config import settings

def send_nft_email(user_email: str, nft_svg: str, nft_id: str, transaction_hash: str):
    """Sends an email with the NFT image and a link to the platform.

    Args:
        user_email: The recipient's email address.
        nft_svg: The SVG data of the NFT.
        nft_id: The ID of the NFT (transaction hash).
        transaction_hash: The Solana transaction hash.
    """
    msg = MIMEMultipart()
    msg['From'] = settings.EMAIL_FROM_ADDRESS
    msg['To'] = user_email
    msg['Subject'] = "Your CRAFT NFT!"

    # Email body
    body = f"""
    <p>Congratulations! You have successfully purchased a CRAFT NFT.</p>
    <p>Here is your NFT: <br><img src="cid:nft_image"></p>
    <p>View NFT details URL to come! </p>
    <p>Transaction Hash: {transaction_hash} <a href='https://explorer.solana.com/tx/{transaction_hash}?cluster=devnet'>View in explorer</a></p>
    """

    msg.attach(MIMEText(body, 'html'))

    # Attach the SVG image
    try:
        img = MIMEImage(nft_svg.encode('utf-8'), 'svg+xml')
        img.add_header('Content-ID', '<nft_image>')
        img.add_header('Content-Disposition', 'inline', filename=f'nft-{nft_id}.svg')
        msg.attach(img)
    except Exception as e:
        print(f"Error attaching image to email: {e}")
        return False

    try:
        server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
        server.starttls()  # Upgrade connection to secure
        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
        server.sendmail(settings.EMAIL_FROM_ADDRESS, user_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False