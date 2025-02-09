# craft-nft-marketplace/backend/celeryconfig.py
import os
from celery.schedules import crontab

broker_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0') #Broker local
result_backend = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0') #Result local, docker is different

task_serializer = 'json'
result_serializer = 'json'
accept_content = ['json']
timezone = 'UTC'
enable_utc = True

beat_schedule = {
    'send-weekly-report': {
        'task': 'app.tasks.send_weekly_report',
        'schedule': crontab(day_of_week=1, hour=9, minute=0), # Executes every monday at 9:00 A.M.
        'args': (),
    },
}