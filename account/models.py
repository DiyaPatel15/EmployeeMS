from django.db import models
from .constants import (EMPLOYEE_DESIGNATION, EMPLOYEE_ROLE, EMPLOYEE_COMPANY, E_PRIORITY, E_MENTOR, IN_OUT,APPROVEL_STATUS,ISSUE_STATUS,TableName, Integers,AMOUNT_TYPE,ALLOWANCE_TYPE,LEAVE_HALF,LEAVE_DAYS,LEAVE_TYPE,EVENT_DAY )


from django.contrib.auth.models import AbstractBaseUser,UserManager
from .managers import UserBaseManager
from datetime import datetime,date,timedelta
import ast
from django.core.exceptions import ValidationError
import inflect
from django.db.models import Sum
import datetime
from django.utils import timezone
from dateutil.relativedelta import relativedelta


# Create your models here.

class Employee(AbstractBaseUser):
    emp_id = models.CharField(max_length=10, help_text="Employee ID",null=True, blank=True)
    emp_name = models.CharField(max_length=30, help_text="Employee Name")
    emp_birthday = models.DateField(null=True)
    emp_email = models.EmailField(max_length=255, unique=True, verbose_name="email")
    emp_contact = models.CharField(max_length=15)
    emp_address = models.TextField(null=False)
    emp_profile = models.ImageField(null=True, blank=True, upload_to='profile_image')
    emp_designation = models.CharField(choices=EMPLOYEE_DESIGNATION, max_length=70, help_text="Employee Designation")
    emp_role = models.CharField(choices=EMPLOYEE_ROLE, max_length=50, help_text="Employee Role")
    emp_company = models.CharField(choices=EMPLOYEE_COMPANY, max_length=50, help_text="Employee Company")
    last_scan_in_time = models.DateTimeField(null=True, blank=True)
    last_scan_out_time = models.DateTimeField(null=True, blank=True)
    total_worked_hours = models.DurationField(default=datetime.timedelta(hours=0))
    status = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    emp_joining_date = models.DateField(null=True, blank=True)
    emp_leaving_date = models.DateField(null=True, blank=True)
    casual_leave_balance = models.IntegerField(default=12)
    sick_leave_balance = models.IntegerField(default=6)



    objects = UserBaseManager()

    USERNAME_FIELD = "emp_email"
    REQUIRED_FIELDS = ["emp_id", "emp_name", "emp_contact", "emp_birthday", "emp_address","emp_joining_date", "emp_leaving_date", "emp_profile", "emp_company",
                       "is_active",
                       "status", "emp_role",
                       "emp_designation"]

    def __str__(self):
        return self.emp_email

    def has_perm(self, perm, obj=None):
        # return self.is_admin
        if self.emp_role == 'Admin':
            return True
        elif self.emp_role == 'HR':
            return True
        else:
            return False

    def has_module_perms(self, app_label):
        return True

    def save(self, *args, **kwargs):
        if self.emp_role == "Admin":
            self.is_admin = True
            self.is_staff = True
        if self.emp_role == "HR":
            self.is_admin = False
            self.is_staff = True
        if self.emp_role == "Employee":
            self.is_admin = False
            self.is_staff = False
        super().save(*args, **kwargs)



class Working_hour(models.Model):
    EMP_Id = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name="hour")
    Punch_Date = models.DateField()
    Punch_In = models.DateTimeField(null=True, blank=True)
    Punch_Out = models.DateTimeField(null=True, blank=True)
    worked_Hours = models.FloatField(default=0)
    Total_Hours = models.FloatField(default=0)
    def save(self, *args, **kwargs):
        # Set the current date if the date is not provided
        if not self.date:
            self.date = date.today()
        super().save(*args, **kwargs)







class Holiday(models.Model):
    # holiday_id = models.AutoField(default=None,primary_key=True)
    holiday_date = models.DateField()
    holiday_name = models.CharField(max_length=50, help_text="Employee Name")
    holiday_day = models.CharField(max_length=50)


class Issue_Ticket(models.Model):
    ticket_emp_id = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name="issue_ticket")
    ticket_name = models.CharField(max_length=50, null=True, blank=True)
    ticket_issue = models.TextField()
    ticket_date = models.DateField(null=True,blank=True)
    ticket_status = models.CharField(max_length=50, choices=ISSUE_STATUS,default="Pending")
    ticket_email = models.EmailField(max_length=100, verbose_name="email", null=True, blank=True)

    def save(self, *args, **kwargs):
        self.ticket_name = self.ticket_emp_id.emp_name
        self.ticket_email = self.ticket_emp_id.emp_email
        self.ticket_date = datetime.datetime.now().date()
        super().save(*args, **kwargs)



class Employee_Task(models.Model):
    E_name = models.CharField(max_length=100)
    E_Card_Link = models.CharField(max_length=100)
    E_Assign_Date = models.DateField(max_length=100)
    E_Mentor = models.CharField(max_length=100, choices=E_MENTOR)
    E_Priority = models.CharField(max_length=100, choices=E_PRIORITY)


class In_Out(models.Model):
    name = models.CharField(max_length=100)
    date = models.DateField()
    type = models.CharField(max_length=50, choices=IN_OUT)
    reason = models.CharField(max_length=1000)
    approvel_status = models.CharField(max_length=50, choices=APPROVEL_STATUS)


class Events(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    start = models.DateTimeField(null=True, blank=True)
    end = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "tblevents"






class SalaryStructure(models.Model):
    structure_name = models.CharField(max_length=100, unique=True, help_text="Structure Name")

    class Meta:
        db_table = TableName.SALARY_STRUCTURE

    def __str__(self):
        return self.structure_name


class EmployeeStatus(models.Model):
    employee_status = models.CharField(max_length=100, unique=True, help_text="Status")

    class Meta:
        db_table = TableName.EMPLOYEE_STATUS

    def __str__(self):
        return self.employee_status


class EmpContract(models.Model):
    user = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name="emp_contract", null=True)
    first_name = models.CharField(max_length=30, help_text="first_name")
    last_name = models.CharField(max_length=30, help_text="last_name")
    ctc = models.DecimalField(default=0.0, decimal_places=2, max_digits=10, null=False, blank=False, help_text="CTC", )
    salary_structure = models.ForeignKey(SalaryStructure, on_delete=models.CASCADE)
    start_date = models.DateField()
    end_date = models.DateField()
    status = models.ForeignKey(EmployeeStatus, on_delete=models.CASCADE)
    out_from_pf = models.BooleanField(default=False, help_text="Out From PF (If Not Mandatory)")

    class Meta:
        db_table = TableName.EMP_CONTRACT

    def check_valid_date(self):
        duration = self.end_date - self.start_date
        if duration.days < 0:
            raise ValidationError("End date must be greater than start date")
        return duration

    def __str__(self):
        return self.first_name

    def monthly_ctc(self):
        self.ctc = self.ctc / Integers.TWELVE

    def save(self, *args, **kwargs):
        self.check_valid_date()
        self.monthly_ctc()
        super().save(*args, **kwargs)

class RulesCategory(models.Model):
    rule_category_name = models.CharField(max_length=25, unique=True, help_text="rule_category_name")
    rule_category_code = models.CharField(max_length=5, unique=True, help_text="rule_category_code")

    class Meta:
        db_table = TableName.RULES_CATEGORY

    def get_rule_category_name(self):
        self.rule_category_name = self.rule_category_name.upper()

    def get_rule_category_code(self):
        self.rule_category_code = self.rule_category_code.upper()

    def save(self, *args, **kwargs):
        self.get_rule_category_name()
        self.get_rule_category_code()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.rule_category_name


class Rule(models.Model):
    name = models.CharField(max_length=25, unique=True)
    code = models.CharField(max_length=15, unique=True)
    category_id = models.ForeignKey(RulesCategory, on_delete=models.CASCADE)
    amount_type = models.CharField(max_length=20, choices=AMOUNT_TYPE)
    amount_value = models.TextField()
    salary_structure_id = models.ForeignKey(SalaryStructure, on_delete=models.CASCADE, null=True, related_name="rules")
    sequence = models.IntegerField()

    class Meta:
        db_table = TableName.RULES

    def __str__(self):
        return self.name

    def get_amount_val(self):
        if self.amount_type == "Fixed":
            try:
                self.amount_value = float(self.amount_value)
            except ValueError as e:
                raise ValidationError(f"Please Enter The Digits {e}")
        else:
            try:
                ast.parse(self.amount_value)
            except SyntaxError as e:
                raise ValidationError(f"Invalid Python Code: {e}")
                # return f"Invalid Python Code {e}"

    def save(self, *args, **kwargs):
        self.get_amount_val()
        super().save(*args, **kwargs)


# def ComputeEmployee(self):


class EmployeePaySlip(models.Model):
    emp_id = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name="employee_pay_slip", null=True)
    start_date = models.DateField(blank=True, null=True)
    end_date = models.DateField(blank=True, null=True)
    total_working_days = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    total_payable_days_count = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    deduct_weekends = models.BooleanField(default=False)

    class Meta:
        db_table = TableName.EMPLOYEE_PAY_SLIP

    def check_valid_date(self):
        duration = self.end_date - self.start_date
        if duration.days < 0:
            raise ValidationError("End date should be greater than Start date")

    def count_weekend_holidays_between_dates(self):
        start_date = self.start_date
        end_date = self.end_date
        weekend_holiday_count = 0

        current_date = start_date
        while current_date <= end_date:
            if current_date.weekday() in [5, 6]:  # Check if it's a Saturday (5) or Sunday (6)
                holiday = Holiday.objects.filter(event_date=current_date).first()
                if holiday:
                    weekend_holiday_count += 1

            current_date += timedelta(days=1)

        return weekend_holiday_count

    def count_leaves(self):
        total_leave_duration = EmployeeLeave.objects.filter(employee=self.emp_id, start_date__gte=self.start_date,
                                                    end_date__lte=self.end_date).aggregate(
            total_duration=Sum(models.F('end_date') - models.F('start_date')))['total_duration']
        if total_leave_duration is None:
            # print(type(total_leave_duration))
            total_leave_duration = 0
        if total_leave_duration:
            total_leave_duration = total_leave_duration.days + 1
            if self.emp_id.casual_leave_balance != 0:
                leaves = self.emp_id.casual_leave_balance - total_leave_duration
                if (leaves < 0):
                    unpaid_leaves = abs(leaves)
                    return unpaid_leaves
                return leaves
            else:
                leaves = total_leave_duration
                return leaves
        else:
            return 0

    def get_saturday_sunday(self):
        saturdays = 0
        sundays = 0

        current_day = self.start_date
        while current_day <= self.end_date:
            if current_day.weekday() == 5:  # Saturday
                saturdays += 1
            elif current_day.weekday() == 6:  # Sunday
                sundays += 1
            current_day += timedelta(days=1)

        total_count = saturdays + sundays
        return total_count

    def get_weekend_holiday(self):
        holidays_in_selected_month = Holiday.objects.filter(
            event_date__range=(self.start_date, self.end_date)).count()
        return holidays_in_selected_month

    def get_month_name(self):
        start_date = self.start_date
        end_date = self.end_date
        months = []
        while start_date < end_date:
            months.append(start_date.strftime("%B"))
            start_date += timedelta(days=30)
        months_string = ""
        for ele in months:
            months_string += ele

        return months_string[:3]

    def total_payable_days(self):
        if self.start_date and self.end_date:
            duration = self.end_date - self.start_date
            total_duration = duration.days
            total_duration = total_duration + 1

            saturday_sunday = self.get_saturday_sunday()
            unpaid_leaves = self.count_leaves()
            # weekend_holiday_count = self.count_weekend_holidays_between_dates()
            if self.deduct_weekends:
                total_working_days = total_duration - saturday_sunday
            else:
                total_working_days = total_duration
            total_payable_days = total_working_days - unpaid_leaves  # - weekend_holiday_count
            return total_working_days, total_payable_days
        return 0, 0

    def number_to_words(self, amount):
        p = inflect.engine()
        words = p.number_to_words(int(amount))
        return words.title()

    def save(self, *args, **kwargs):
        self.check_valid_date()
        self.total_working_days, self.total_payable_days_count = self.total_payable_days()
        super().save(*args, **kwargs)


class EmployeePaySlipLines(models.Model):
    slip_id = models.ForeignKey(EmployeePaySlip, on_delete=models.CASCADE, related_name="employee_pay_slip_lines")
    name = models.CharField(max_length=25)
    code = models.CharField(max_length=10)
    category_id = models.ForeignKey(RulesCategory, on_delete=models.CASCADE)
    amount_type = models.CharField(max_length=20, choices=AMOUNT_TYPE, default="Fixed")
    amount_value = models.TextField()
    rate = models.FloatField()
    final = models.FloatField()



class EmployeeLeave(models.Model):
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name="employee_leaves")
    leave_type = models.CharField(max_length=50, choices=LEAVE_TYPE)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    leave_days = models.CharField(choices=LEAVE_DAYS, max_length=30)
    leave_half = models.CharField(choices=LEAVE_HALF, max_length=30, null=True, blank=True)
    no_leave_days = models.FloatField(null=True, blank=True)
    leave_reason = models.TextField()
    approval_status = models.CharField(max_length=50, choices=APPROVEL_STATUS, default='Pending')

    def __str__(self):
        return str(self.employee)

    def save(self, *args, **kwargs):

        if self.leave_days == "Full":
            leave_duration = (self.end_date - self.start_date).days + 1
            self.no_leave_days = leave_duration

            if self.leave_type == "Casual Leave":
                self.employee.casual_leave_balance -= leave_duration
            elif self.leave_type == "Sick Leave":
                if self.leave_days != "Half":
                    self.employee.sick_leave_balance -= leave_duration
                else:
                    self.employee.sick_leave_balance -= 0.5
        else:
            self.end_date = self.start_date
            if self.leave_type == "Casual Leave":
                self.employee.casual_leave_balance -= 0.5
            elif self.leave_type == "Sick Leave":
                self.employee.sick_leave_balance -= 0.5
            self.no_leave_days = 0.5
        super().save(*args, **kwargs)





