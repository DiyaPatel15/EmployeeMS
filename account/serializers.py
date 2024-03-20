from rest_framework.serializers import ModelSerializer
from .models import Employee,Issue_Ticket,Holiday,Employee_Task,In_Out
from rest_framework import serializers
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from account.utils import Util



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
        fields = ['ticket_email', 'ticket_issue']

class HolidaySerializer(ModelSerializer):
    class Meta:
        model= Holiday
        fields = ['id', 'holiday_date', 'holiday_name', 'holiday_day']



class EmployeeTaskSerializer(ModelSerializer):
    class Meta:
        model = Employee_Task
        fields = ['E_name', 'E_Card_Link', 'E_Assign_Date', 'E_Mentor', 'E_Priority']


class In_Out_serializer(ModelSerializer):
    class Meta:
        model = In_Out
        fields = '__all__'



