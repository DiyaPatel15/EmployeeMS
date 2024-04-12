from django.urls import path, include
from .views import (EmployeeViewSet, EmployeeRegistrationView, EmployeeLoginView, TokenRefreshView, EmployeeLogoutView,
                    EmployeeProfileView, EmployeeChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView,
                    scan_qr_code, generate_qr_code, IssueTicketViewSet, issue_ticket, holidayViewSet,
                    holidayView, employee_task_View, EmployeeTaskViewSet, inoutViewSet, inout_view,
                    SalaryStructureViewSet, EmployeeStatusViewSet, EmpContractViewSet, RuleCategoryViewSet, RuleViewSet,
                    EmployeePaySlipViewSet, EmployeePaySlipLinesViewSet, EmployeeLeaveViewSet, IssueTicketUserViewSet)
from rest_framework.routers import DefaultRouter
from account import views
from django.conf import settings
from django.conf.urls.static import static
from account.views import compute_employee, print_payslip

router = DefaultRouter()

router.register(r"emp-list", EmployeeViewSet, basename="Employee List")
router.register(r"emp-task", EmployeeTaskViewSet, basename="Employee task")
router.register(r"issue-ticket", IssueTicketViewSet, basename="Issue Ticket")
router.register(r"holidays", holidayViewSet, basename="holidays")
router.register(r"in-out", inoutViewSet, basename="in-out")
router.register(r"employee-leave", EmployeeLeaveViewSet, basename="employee_leave")
router.register("salary-structure", SalaryStructureViewSet, basename="salary_structure")
router.register("employee-status", EmployeeStatusViewSet, basename="employee_status")
router.register("emp-contract", EmpContractViewSet, basename="emp_contract")
router.register("rule-category", RuleCategoryViewSet, basename="rule_category")
router.register("rule", RuleViewSet, basename="rule")
router.register('employee-pay-slip', EmployeePaySlipViewSet, basename="employee_pay_slip")
router.register('employee-pay-slip-lines', EmployeePaySlipLinesViewSet, basename="employee_pay_slip_lines")

urlpatterns = [
                  path('', include(router.urls)),
                  path('register/', EmployeeRegistrationView.as_view(), name="register"),
                  path('login/', EmployeeLoginView.as_view(), name="login"),
                  path('refreshtoken/', TokenRefreshView.as_view(), name="refreshtoken"),
                  path('logout/', EmployeeLogoutView.as_view(), name="logout"),
                  path("profile/", EmployeeProfileView.as_view(), name="profile"),
                  path("changepassword/", EmployeeChangePasswordView.as_view(), name="changepassword"),
                  path('send-password-reset-email/', SendPasswordResetEmailView.as_view(),
                       name="SendPasswordResetEmail"),
                  path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name="reset_password"),
                  path('scan/', scan_qr_code, name='scan_qr_code'),
                  path('generate-qr/', generate_qr_code, name='generate_qr_code'),
                  path('home/', views.home, name="home"),
                  path('forgot_pass/', views.forgot, name="forgot_pass"),
                  path('change_pass/', views.changepassword, name="change_pass"),
                  path('dashboard/', views.dashboard, name="dashboard"),
                  path('emp-list-data/', views.employee_list, name="emplistdata"),
                  path('issueticket/', issue_ticket, name="issueticket"),
                  path('holidayView/', holidayView, name="holidayView"),
                  path('employeetask/', employee_task_View, name='employeetask'),
                  path('emp-leave/', views.leave, name="emp-leave"),
                  path('inout/', inout_view, name='inout'),
                  path('inoutlist/', views.in_out_list, name='inoutlist'),
                  path('calendar/', views.Calendar, name='calendar'),
                  path('all_events/', views.all_events, name='all_events'),
                  path('add_event/', views.add_event, name='add_event'),
                  path('update/', views.update, name='update'),
                  path('remove/', views.remove, name='remove'),
                  path('issueticketuser/', views.IssueTicketUserViewSet.as_view(), name='issueticketuser'),
                  path('leaveuser/', views.EmployeeLeaveView.as_view(), name='leaveuser'),
                  path('taskuser/', views.EmployeeTaskView.as_view(), name='taskuser'),
                  path('inoutuser/', views.EmployeeInOutView.as_view(), name='inoutuser'),
                  path('api/<int:payslip_id>/calculate_payslip/', compute_employee, name='employee_pay_slip'),
                  path('api/<int:payslip_id>/generate_payslip/', print_payslip, name='generate_pay_slip'),

              ] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
