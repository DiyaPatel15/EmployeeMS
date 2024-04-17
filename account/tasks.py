from django.utils import timezone
from celery import shared_task
from datetime import timedelta
from django.core.mail import EmailMessage
from account import models


@shared_task
def send_email_before_end_date():
    one_week_from_now = timezone.now() + timedelta(days=7)
    employees_to_notify = models.EmpContract.objects.filter(end_date__lte=one_week_from_now)

    # print("################################")
    for employee in employees_to_notify:
        # print("#########################33")
        subject = 'Contract Renewal Reminder'
        message = f'''
<html>
<head></head>
<body>
Dear HR,

<p>I hope this email finds you well. We wanted to bring to your attention that the contract for <b>{employee.first_name} {employee.last_name}</b> is going to expire on <b>{employee.end_date}</b>. As of today, there is only one week left until the contract's expiration date.</p>

Please do needful.<br/>
Thanks and Regards.
</body>
</html>
'''
        from_email = 'yogeshgoswami0306@gmail.com'
        recipient_list = ['hr@pranshtech.com']

        # send_mail(subject, message, from_email, recipient_list)
        email = EmailMessage(subject, message, from_email, recipient_list)
        email.content_subtype = 'html'
        email.send()
