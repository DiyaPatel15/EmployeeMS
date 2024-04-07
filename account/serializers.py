from rest_framework.serializers import ModelSerializer
from .models import Employee,Issue_Ticket,Holiday,Employee_Task,In_Out,SalaryStructure, EmployeeStatus, EmpContract, RulesCategory, Rule,EmployeePaySlip, EmployeePaySlipLines,Leave
from rest_framework import serializers
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from account.utils import Util
import ast



class EmployeeSerializer(ModelSerializer):
    class Meta:
        model = Employee
        fields = "__all__"






class RelativeImageField(serializers.ImageField):
    def to_representation(self, value):
        if value:
            return value.url
        return None


class EmployeeRegistrationSerializer(ModelSerializer):
    class Meta:
        model = Employee
        fields = "__all__"
        extra_kwargs = {
            'password': {'write_only': True}
        }
    def create(self, validated_data):
        return Employee.objects.create_user(**validated_data)

class EmployeeLoginSerializer(ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = Employee
        fields = ['email', 'password']


class EmployeeProfileSerializer(ModelSerializer):
    class Meta:
        model = Employee
        fields = '__all__'



class EmployeeChangePasswordSerializer(ModelSerializer):
    password = serializers.CharField(max_length=50, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=50, style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = Employee
        fields = ['password', 'password2']

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and Password2 Doesn't Matched")
        user.set_password(password)
        user.save()
        return super().validate(data)



class SendPasswordResetSerializer(ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = Employee
        fields = ['email']

    def validate(self, data):
        email = data.get("email")
        if Employee.objects.filter(emp_email=email).exists():
            employee = Employee.objects.get(emp_email=email)
            uid = urlsafe_base64_encode(force_bytes(employee.id))
            token = PasswordResetTokenGenerator().make_token(employee)
            link = "http://127.0.0.1:8000/user/reset/" + uid + "/" + token

            data['uid'] = uid
            data['token'] = token
            data['link'] = link
            body = 'Click Following Link to Reset Your Password ' + link
            data = {
                'subject': 'Reset Your Password',
                'body': body,
                'to_email': employee.emp_email
            }
            Util.send_mail(data)
        else:
            raise ValueError("You Are Not Registered")
        data['uid'] = uid
        data['token'] = token
        data['link'] = link
        return data


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input-type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input-type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("Password and Confirm Password Doesn't Match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = Employee.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("Token is not valid or expired")

            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError("Token is not valid or expired")


class IssueTicketSerializer(ModelSerializer):
    class Meta:
        model = Issue_Ticket
        fields = '__all__'



class HolidaySerializer(ModelSerializer):
    class Meta:
        model= Holiday
        fields = ['id', 'holiday_date', 'holiday_name', 'holiday_day']



class EmployeeTaskSerializer(ModelSerializer):
    class Meta:
        model = Employee_Task
        fields = '__all__'


class In_Out_serializer(ModelSerializer):
    class Meta:
        model = In_Out
        fields = '__all__'


class SalaryStructureSerializer(serializers.ModelSerializer):
    class Meta:
        model = SalaryStructure
        fields = ['id', 'structure_name']


class EmployeeStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployeeStatus
        fields = ['id', 'employee_status']


class EmpContractSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmpContract
        fields = ['id', 'user', 'first_name', 'last_name', 'ctc', 'salary_structure', 'start_date', 'end_date',
                  'status']


class RuleCategorySerializer(serializers.ModelSerializer):
    # id = serializers.IntegerField(allow_null=True)
    class Meta:
        model = RulesCategory
        fields = ['id', 'rule_category_name', 'rule_category_code']


class RuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rule
        fields = ['id', 'name', 'code', 'category_id', 'amount_type', 'amount_value', 'salary_structure_id']

    def validate(self, data):
        amt_type = data.get('amount_type')
        amt_value = data.get('amount_value')

        if amt_type == "Python Code" or amt_type != "Fixed":
            try:
                ast.parse(amt_value)
            except SyntaxError as e:
                raise serializers.ValidationError(f"Invalid Python Code {e}")

        if amt_type == "Fixed":

            try:
                amt_value = float(amt_value)
            except ValueError as e:
                raise serializers.ValidationError(f"Please Enter The Digits {e}")

        return data


class EmployeePaySlipSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployeePaySlip
        fields = ['id', 'emp', 'start_date', 'end_date', 'total_working_days', 'total_payable_days_count']

    def validate(self, data):
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        duration = end_date - start_date
        if duration.days < 0:
            raise serializers.ValidationError("End date should be greater than Start date")
        return data


class EmployeePaySlipLinesSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployeePaySlipLines
        fields = ["id", "slip_id", "name", "code", "category_id", "amount_type", "amount_value", "rate", "final"]

class LeaveSerializer(serializers.ModelSerializer):
    class Meta:
        model = Leave
        fields = ['id', 'emp_id', "leave_type", "leave_day", "from_date", "to_date", "status"]



