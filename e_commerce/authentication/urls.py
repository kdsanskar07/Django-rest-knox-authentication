from django.urls import path
from .views import RegisterAPIView, VerifyEmailAPIView, LoginAPIView, ResetPasswordRequestAPIView, \
    PasswordTokenCheckAPIView, \
    SetNewPasswordAPIView, RequestEmailverifyAPIView
from knox.views import LogoutAllView, LogoutView

urlpatterns = [
    path('register/', RegisterAPIView.as_view(), name='Register user'),
    path('request-verify-email', RequestEmailverifyAPIView.as_view(), name='request-verify-email'),
    path('email-verify/', VerifyEmailAPIView.as_view(), name='email-verify'),
    path('login/', LoginAPIView.as_view(), name='user-login'),
    path('logout/', LogoutView.as_view(), name='knox-logout'),
    path('logoutall/', LogoutAllView.as_view(), name='knox-logout-all'),
    path('request-reset-password/', ResetPasswordRequestAPIView.as_view(), name="request-reset-pasword"),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheckAPIView.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(), name='password-reset-complete')
]
