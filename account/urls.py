from django.urls import path, include
from .views import (EmployeeViewSet, EmployeeRegistrationView, EmployeeLoginView, TokenRefreshView, EmployeeLogoutView,
                    EmployeeProfileView, EmployeeChangePasswordView, SendPasswordResetEmailView, UserPasswordResetView,
                    scan_qr_code, generate_qr_code, IssueTicketViewSet, issue_ticket, holidayViewSet,
                    update_holidayView, holidayView, holiday_add_view, employee_task_View, EmployeeTaskViewSet,inoutViewSet,inout_view)
from rest_framework.routers import DefaultRouter
from account import views
from django.conf import settings
from django.conf.urls.static import static

router = DefaultRouter()

router.register(r"emp-list", EmployeeViewSet, basename="Employee List")
router.register(r"emp-task", EmployeeTaskViewSet, basename="Employee task")
router.register(r"issue-ticket", IssueTicketViewSet, basename="Issue Ticket")
router.register(r"holidays", holidayViewSet, basename="holidays")
router.register(r"in-out", inoutViewSet, basename="in-out")

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
                  path('update_holiday/<int:pk>', update_holidayView, name="update_holiday"),
                  path('holidayView/', holidayView, name="holidayView"),
                  path('holiday/add/', holiday_add_view, name='holiday_add'),
                  path('employeetask/', employee_task_View, name='employeetask'),
                  path('inout/', inout_view, name='inout'),

              ] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
