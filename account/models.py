from django.db import models
from .constants import EMPLOYEE_DESIGNATION, EMPLOYEE_ROLE, EMPLOYEE_COMPANY, E_PRIORITY, E_MENTOR,IN_OUT,APPROVEL_STATUS
from django.contrib.auth.models import AbstractBaseUser
from .managers import UserBaseManager


# Create your models here.

class Employee(AbstractBaseUser):
    emp_id = models.CharField(max_length=10, help_text="Employee ID")
    emp_name = models.CharField(max_length=30, help_text="Employee Name")
    emp_email = models.EmailField(max_length=255, unique=True, verbose_name="email")
    emp_contact = models.CharField(max_length=15)
    emp_address = models.TextField(null=False)
    emp_profile = models.ImageField(null=True, blank=True, upload_to='profile_image')
    emp_designation = models.CharField(choices=EMPLOYEE_DESIGNATION, max_length=70, help_text="Employee Designation")
    emp_role = models.CharField(choices=EMPLOYEE_ROLE, max_length=50, help_text="Employee Role")
    emp_company = models.CharField(choices=EMPLOYEE_COMPANY, max_length=50, help_text="Employee Company")
    status = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserBaseManager()

    USERNAME_FIELD = "emp_email"
    REQUIRED_FIELDS = ["emp_id", "emp_name", "emp_contact", "emp_address", "emp_profile", "emp_company", "is_active",
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


class Holiday(models.Model):
    # holiday_id = models.AutoField(default=None,primary_key=True)
    holiday_date = models.DateField()
    holiday_name = models.CharField(max_length=50, help_text="Employee Name")
    holiday_day = models.CharField(max_length=50)


class Issue_Ticket(models.Model):
    ticket_email = models.EmailField(max_length=255, verbose_name="email")
    ticket_issue = models.TextField()


class Employee_Task(models.Model):
    E_name = models.CharField(max_length=100)
    E_Card_Link = models.CharField(max_length=100)
    E_Assign_Date = models.DateField(max_length=100)
    E_Mentor = models.CharField(max_length=100, choices=E_MENTOR)
    E_Priority = models.CharField(max_length=100, choices=E_PRIORITY)

class In_Out(models.Model):
    name = models.CharField(max_length=100)
    date = models.DateField()
    type = models.CharField(max_length=50,choices=IN_OUT)
    reason = models.CharField(max_length=1000)
    approvel_status = models.CharField(max_length=50,choices=APPROVEL_STATUS)