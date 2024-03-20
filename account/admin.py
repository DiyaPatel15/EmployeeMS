from django.contrib import admin

# Register your models here.
from .models import Employee,Holiday,Issue_Ticket,Employee_Task,In_Out

admin.site.register(Employee),
admin.site.register(Holiday),
admin.site.register(Issue_Ticket),
admin.site.register(Employee_Task),
admin.site.register(In_Out)