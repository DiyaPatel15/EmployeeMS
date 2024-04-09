from django.shortcuts import render
from .models import Employee, Issue_Ticket, Holiday, Employee_Task, In_Out,Events,SalaryStructure, EmployeeStatus, EmpContract, RulesCategory, Rule,EmployeePaySlip,EmployeePaySlipLines,Leave
from .serializers import (EmployeeSerializer, EmployeeRegistrationSerializer, EmployeeLoginSerializer,In_Out_serializer,EmployeeProfileSerializer, EmployeeChangePasswordSerializer, UserPasswordResetSerializer,
                          SendPasswordResetSerializer, IssueTicketSerializer, HolidaySerializer, EmployeeTaskSerializer,SalaryStructureSerializer,
                          EmployeeStatusSerializer, EmpContractSerializer, RuleCategorySerializer, RuleSerializer,
                          EmployeePaySlipSerializer, EmployeePaySlipLinesSerializer,LeaveSerializer)
from rest_framework.viewsets import ModelViewSet
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import authenticate, login, logout
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view
from django.http import HttpResponse, JsonResponse
from rest_framework.filters import SearchFilter
from rest_framework import filters
import qrcode
from datetime import datetime
from datetime import timedelta
from rest_framework.decorators import api_view, permission_classes
import re
import inflect
from xhtml2pdf import pisa
from django.template.loader import get_template


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class EmployeeViewSet(ModelViewSet):
    # permission_classes = [IsAuthenticated]
    queryset = Employee.objects.all()
    serializer_class = EmployeeSerializer





class EmployeeTaskViewSet(ModelViewSet):
    queryset = Employee_Task.objects.all()
    serializer_class = EmployeeTaskSerializer


class EmployeeRegistrationView(APIView):
    def post(self, request, format=None):
        serializer = EmployeeRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmployeeLoginView(APIView):
    def post(self, request, format=None):
        serializer = EmployeeLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get("email")
            password = serializer.data.get("password")
            user = authenticate(emp_email=email, password=password)
            print(user)
            if user:
                login(request, user)
                token = get_tokens_for_user(user)
                return Response(token, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Email or Password is not valid"}, status=status.HTTP_400_BAD_REQUEST)

        else:
            return Response({"error": "Email or Password is not valid"}, status=status.HTTP_400_BAD_REQUEST)


class TokenRefreshView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({"error": "Refresh Token Not Provided"}, status=status.HTTP_400_BAD_REQUEST)

            refresh = RefreshToken(refresh_token)
            new_access_token = str(refresh.access_token)
            return Response({"access": new_access_token}, status=status.HTTP_200_OK)
        except:
            return Response({"error": "Invalid Data"})


class EmployeeLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({"error": "Refresh token not provided"}, status=status.HTTP_400_BAD_REQUEST)

            else:
                token = RefreshToken(refresh_token)
                token.blacklist()
                logout(request)
                return Response({"message": "Logout Successful"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class EmployeeProfileView(APIView):
    def get(self, request, format=None):
        try:
            serializer = EmployeeProfileSerializer(request.user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except:
            return Response({"error": "Anonymous User"}, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, format=None):
        try:
            user_profile = request.user
            serializer = EmployeeProfileSerializer(user_profile, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response({"error": "Anonymous User"}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, format=None):
        try:
            request.user.delete()
            return Response({"message": "User Deleted Successfully"}, status=status.HTTP_200_OK)
        except:
            return Response({"Error": "User is not Logged In"}, status=status.HTTP_400_BAD_REQUEST)


class EmployeeChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        try:
            serializer = EmployeeChangePasswordSerializer(data=request.data, context={'user': request.user})
            if serializer.is_valid():
                return Response({'detail': "Password Updated Successfully"}, status=status.HTTP_200_OK)
            return Response({"error": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response({"error": "Unexpected Error"}, status=status.HTTP_400_BAD_REQUEST)


class SendPasswordResetEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, format=None):
        serializer = SendPasswordResetSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            uid = serializer.validated_data.get('uid')
            token = serializer.validated_data.get('token')
            link = serializer.validated_data.get('link')
            return Response({"message": "Password Reset Link Is Been Send", "uid": uid, "token": token, "link": link})
        return Response({"message": "There was an unexpected error"})


class UserPasswordResetView(APIView):
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
        if serializer.is_valid(raise_exception=True):
            return Response({'message': "Password Reset Successfully"})
        return Response(serializer.errors)


@api_view(['GET'])
def generate_qr_code(request):
    try:
        # Assuming you have only one employee for simplicity
        employee = Employee.objects.get(id=26)

        # Generate QR code data based on employee ID
        qr_code_data = f"employee_id:{employee.id}"

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_code_data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        response = HttpResponse(content_type="image/png")
        img.save(response, "PNG")
        return response

    except Employee.DoesNotExist:
        return Response({"error": "Employee not found"}, status=status.HTTP_404_NOT_FOUND)



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def scan_qr_code(request):
    try:
        qr_code_data = request.data.get('qr_code_data')
        employee_id = int(qr_code_data.split(":")[1])

        # Lookup employee by employee_id
        employee = Employee.objects.get(id=employee_id)

        # Update time entry based on employee's current status
        current_time = datetime.now()
        if employee.status:
            # This is an out-time scan
            employee.last_scan_out_time = current_time
        else:
            # This is an in-time scan
            employee.last_scan_in_time = current_time

        # Toggle employee status
        employee.status = not employee.status
        employee.save()

        total_hours_worked = timedelta(0)
        if employee.last_scan_in_time and employee.last_scan_out_time:
            total_hours_worked = employee.last_scan_out_time - employee.last_scan_in_time

        return Response(
            {"message": "Time entry updated successfully", "id": employee_id, "total_hours_worked": total_hours_worked},
            status=status.HTTP_200_OK)

    except (Employee.DoesNotExist, ValueError, IndexError):
        return Response({"error": "Invalid QR code data or Employee does not exist"},
                        status=status.HTTP_400_BAD_REQUEST)

class IssueTicketViewSet(ModelViewSet):
    serializer_class = IssueTicketSerializer
    queryset = Issue_Ticket.objects.all()


    def submit_ticket(request):
        if request.method == 'POST':
            # Process the ticket submission here

            # Example ticket data
            ticket_issue = request.POST.get('ticket_issue')
            ticket_emp_id = request.POST.get('ticket_emp_id')
            ticket_date = request.POST.get('ticket_date')

            # Send email to admin
            subject = 'New Ticket Submitted'
            message = f'A new ticket has been submitted.\n\nIssue: {ticket_issue}\nEmployee ID: {ticket_emp_id}\nDate: {ticket_date}'
            from_email = 'mailto:foram.pranshtech@gmail.com'  # Sender's email address
            recipient_list = 'mailto:rupesh@pranshtech.com'  # Admin's email address

            send_mail(subject, message, from_email, recipient_list)

            return JsonResponse({'message': 'Ticket submitted and email sent to admin'})
        else:
            return JsonResponse({'error': 'Invalid request method'}, status=405)



class holidayViewSet(ModelViewSet):
    # permission_classes = [IsAuthenticated]
    serializer_class = HolidaySerializer
    queryset = Holiday.objects.all()


class inoutViewSet(ModelViewSet):
    # permission_classes = [IsAuthenticated]
    serializer_class = In_Out_serializer
    queryset = In_Out.objects.all()


def home(request):
    return render(request, 'account/authentication.html')


def issue_ticket(request):
    return render(request, 'account/issue_ticket.html')


def forgot(request):
    return render(request, 'account/forgot.html')


def changepassword(request):
    return render(request, 'account/changepassword.html')


def dashboard(request):
    return render(request, 'account/dashboard.html')


def employee_list(request):
    return render(request, 'account/new_emp_list.html')


def holidayView(request):
    form = Holiday.objects.all()
    print(form)
    return render(request, 'account/holidays.html', {'form': form})


def employee_task_View(request):
    return render(request, 'account/employee_task.html')

def emp_leave(request):
    return render(request, 'account/employee_leave.html')


def inout_view(request):
    form = In_Out.objects.all()
    print(form)
    return render(request, 'account/in-out.html', {'form': form})


def Calendar(request):
    all_events = Events.objects.all()
    context = {
        "events": all_events,
    }
    return render(request, 'account/calendar.html', context)


def all_events(request):
    all_events = Events.objects.all()
    out = []
    for event in all_events:
        out.append({
            'title': event.name,
            'id': event.id,
            'start': event.start.strftime("%m/%d/%Y, %H:%M:%S"),
            'end': event.end.strftime("%m/%d/%Y, %H:%M:%S"),
        })

    return JsonResponse(out, safe=False)


def add_event(request):
    start = request.GET.get("start", None)
    end = request.GET.get("end", None)
    title = request.GET.get("title", None)
    event = Events(name=str(title), start=start, end=end)
    event.save()
    data = {}
    return JsonResponse(data)


def update(request):
    start = request.GET.get("start", None)
    end = request.GET.get("end", None)
    title = request.GET.get("title", None)
    id = request.GET.get("id", None)
    event = Events.objects.get(id=id)
    event.start = start
    event.end = end
    event.name = title
    event.save()
    data = {}
    return JsonResponse(data)


def remove(request):
    id = request.GET.get("id", None)
    event = Events.objects.get(id=id)
    event.delete()
    data = {}
    return JsonResponse(data)


class LeaveViewSet(ModelViewSet):
    queryset = Leave.objects.all()
    serializer_class = LeaveSerializer
class SalaryStructureViewSet(ModelViewSet):
    queryset = SalaryStructure.objects.all()
    serializer_class = SalaryStructureSerializer


class EmployeeStatusViewSet(ModelViewSet):
    queryset = EmployeeStatus.objects.all()
    serializer_class = EmployeeStatusSerializer


class EmpContractViewSet(ModelViewSet):
    queryset = EmpContract.objects.all()
    serializer_class = EmpContractSerializer


class RuleCategoryViewSet(ModelViewSet):
    queryset = RulesCategory.objects.all()
    serializer_class = RuleCategorySerializer


class RuleViewSet(ModelViewSet):
    queryset = Rule.objects.all()
    serializer_class = RuleSerializer


class EmployeePaySlipViewSet(ModelViewSet):
    queryset = EmployeePaySlip.objects.all()
    serializer_class = EmployeePaySlipSerializer


@api_view(['GET', 'POST'])
def compute_employee(request, payslip_id):
    try:
        payslip = EmployeePaySlip.objects.get(pk=payslip_id)
        payslip.employee_pay_slip_lines.all().delete()
        # variable that can be used in python code
        employee = payslip.emp
        contract = employee.emp_contract.latest("id")
        contra = f"EmployeePaySlip.objects.get(pk={str(payslip_id)}).emp.emp_contract.latest('id')"
        ordered_rules = contract.salary_structure.rules.order_by("sequence")
        # basic_total = sum(payslip.employee_pay_slip_lines.filter(category_id__rule_category_code__in=['BASIC']).values_list('rate', flat=True))
        # allowance = sum(payslip.employee_pay_slip_lines.filter(category_id__rule_category_code__in=['ALW']).values_list('rate', flat=True))

        # import pdb; pdb.set_trace()
        print(ordered_rules)
        for rule in ordered_rules:
            local_var = {}
            if rule.amount_type == 'Python Code':
                # print(basic_total)
                python_code = rule.amount_value
                python_code = python_code.replace('contract', contra)
                matches = re.findall(r'rules\.\w*', python_code)
                # if contract.salary_structure.structure_name == "Regular Salary":
                #     matches = re.findall(r'rules\.\w*', python_code)
                # elif contract.salary_structure.structure_name == "Salary Without PF":
                #     matches = re.findall(r'rules\.(?!HRA|PFEN1|PFEPS|PFEMP)\w*', python_code)
                for match in matches:
                    temp_rule = f"EmployeePaySlip.objects.get(pk={str(payslip_id)}).employee_pay_slip_lines.get(code='RULE_CODE').rate"
                    code = match.split('.')[-1]
                    if code:
                        temp_rule = temp_rule.replace('RULE_CODE', code)
                        python_code = python_code.replace(match, temp_rule)
                exec(python_code, globals(), local_var)
                res = local_var['result']
            else:
                res = rule.amount_value

            total_days = payslip.total_payable_days()[0]
            worked_days = payslip.total_payable_days()[1]

            if total_days == worked_days:
                final_total = res
            else:
                oneday_amount = float(res) / total_days
                final_total_value = float(oneday_amount) * float(worked_days)
                formatted_final_total = f"{final_total_value:.2f}"
                final_total = float(formatted_final_total)

            result = EmployeePaySlipLines.objects.create(
                slip_id=payslip,
                name=contract.first_name,
                code=rule.code,
                category_id=rule.category_id,
                amount_type=rule.amount_type,
                amount_value=rule.amount_value,
                rate=res,
                final=final_total
            )
            print(result)

        payslip_lines = payslip.employee_pay_slip_lines.all()
        # if contract.out_from
        serializer = EmployeePaySlipLinesSerializer(payslip_lines, many=True)
        return Response({"data": serializer.data})

        # return JsonResponse({"data": json_data}, content_type='application/json')
    except EmployeePaySlip.DoesNotExist:
        return Response({"error": "Not Exist"}, status=status.HTTP_404_NOT_FOUND)


class EmployeePaySlipLinesViewSet(ModelViewSet):
    queryset = EmployeePaySlipLines.objects.all()
    serializer_class = EmployeePaySlipLinesSerializer


@api_view(['GET'])
def print_payslip(request, payslip_id):
    # import pdb;
    # pdb.set_trace()
    try:
        payslip = EmployeePaySlip.objects.get(pk=payslip_id)
    except EmployeePaySlip.DoesNotExist:
        return HttpResponse({"error": "Not Exist"}, status=status.HTTP_404_NOT_FOUND)

    net_amount = sum(
        payslip.employee_pay_slip_lines.filter(category_id__rule_category_code__in=['BASIC', 'ALW']).values_list(
            'final', flat=True)) - sum(
        payslip.employee_pay_slip_lines.filter(category_id__rule_category_code__in=['DED']).values_list('final',
                                                                                                        flat=True))

    net_amount_total = sum(
        payslip.employee_pay_slip_lines.filter(category_id__rule_category_code__in=['BASIC', 'ALW']).values_list('rate',
                                                                                                                 flat=True)) - sum(
        payslip.employee_pay_slip_lines.filter(category_id__rule_category_code__in=['DED']).values_list('rate',
                                                                                                        flat=True))

    std_days = payslip.total_payable_days()[0]
    worked_days = payslip.total_payable_days()[1]
    lop = std_days - worked_days

    print(payslip.emp.emp_contract.latest("id").ctc)
    payslip_template = get_template('payslip.html')
    context = {
        'payslip': payslip,
        "first_name": payslip.emp.emp_contract.latest("id").first_name,
        "last_name": payslip.emp.emp_contract.latest("id").last_name,
        "ctc": payslip.emp.emp_contract.latest("id").ctc,
        "month": payslip.get_month_name(),
        "data": {payslip_data.code: payslip_data.final for payslip_data in payslip.employee_pay_slip_lines.all()},
        "rate": {payslip_data.code: payslip_data.rate for payslip_data in payslip.employee_pay_slip_lines.all()},
        "gross_earnings": sum(
            payslip.employee_pay_slip_lines.filter(category_id__rule_category_code__in=['BASIC', 'ALW']).values_list(
                'final', flat=True)),
        "gross_deductions": sum(
            payslip.employee_pay_slip_lines.filter(category_id__rule_category_code__in=['DED']).values_list('final',
                                                                                                            flat=True)),
        "net_amount": net_amount,
        "gross_earnings_total": sum(
            payslip.employee_pay_slip_lines.filter(category_id__rule_category_code__in=['BASIC', 'ALW']).values_list(
                'rate', flat=True)),
        "gross_deductions_total": sum(
            payslip.employee_pay_slip_lines.filter(category_id__rule_category_code__in=['DED']).values_list('rate',
                                                                                                            flat=True)),
        "net_amount_total": net_amount_total,
        "net_amount_words": payslip.number_to_words(net_amount),
        "std_days": std_days,
        "worked_days": worked_days,
        "lop": lop,
    }

    html = payslip_template.render(context)

    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'filename="payslip.pdf"'

    # Generate PDF
    pisa_status = pisa.CreatePDF(html, dest=response)

    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')

    return response





