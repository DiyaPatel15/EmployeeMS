from django.contrib.auth.models import BaseUserManager


class UserBaseManager(BaseUserManager):
    def create_user(self, emp_id, emp_name,emp_birthday, emp_email,emp_contact,emp_address, emp_profile, emp_designation, emp_role, emp_company,bank_name=None, pf_number=None, bank_account_number=None, uan=None,
                    password=None, **extra_fields):
        if not emp_email:
            raise ValueError("Email is Required")
        user = self.model(emp_id=emp_id, emp_name=emp_name,emp_birthday=emp_birthday, emp_email=emp_email,emp_contact=emp_contact,emp_address=emp_address,emp_profile=emp_profile, emp_designation=emp_designation, emp_role=emp_role,
                          emp_company=emp_company, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, emp_id, emp_name,emp_birthday, emp_email,emp_contact,emp_address,emp_profile, emp_designation, emp_role,
                         emp_company, password=None, **extra_fields):
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('is_staff', True)

        if extra_fields.get('is_admin') is not True:
            raise ValueError("is_admin must be true")
        if extra_fields.get('is_staff') is not True:
            raise ValueError("is_superuser must be true")

        return self.create_user(emp_id, emp_name,emp_birthday, emp_email,emp_contact, emp_address,emp_profile, emp_designation, emp_role,
                                emp_company, password=password, **extra_fields)
