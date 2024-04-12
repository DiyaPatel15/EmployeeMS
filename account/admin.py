from django.contrib import admin

# Register your models here.
from .models import Employee,Holiday,Issue_Ticket,Employee_Task,In_Out,Events,SalaryStructure, EmpContract, EmployeeStatus, RulesCategory, Rule, EmployeePaySlip, EmployeePaySlipLines,EmployeeLeave

admin.site.register(Employee),
admin.site.register(Holiday),
admin.site.register(Issue_Ticket),
admin.site.register(Employee_Task),
admin.site.register(In_Out),
admin.site.register(Events),
admin.site.register(SalaryStructure),
admin.site.register(EmpContract),
admin.site.register(EmployeeStatus),
admin.site.register(RulesCategory),
admin.site.register(Rule),
admin.site.register(EmployeePaySlip),
admin.site.register(EmployeePaySlipLines),
admin.site.register(EmployeeLeave)

