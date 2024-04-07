from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'employee_management.settings')

app = Celery('employee_management')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks()

# Define a periodic task
app.conf.beat_schedule = {
    'daily_task': {
        'task': 'payroll.tasks.send_email_before_end_date',
        'schedule': crontab(hour=19, minute=44),  # Run daily at 12:00 PM
    },
}
