from django.urls import path
from .views import LoginView, RegisterView, VerifyEmail, RequestResetPasswordView, SetNewPasswordAPIView

urlpatterns = [
    path('signup', RegisterView.as_view(), name='signup'),
    path('email-verify', VerifyEmail.as_view(), name='email-verify'),
    path('login', LoginView.as_view(), name='login'),
    path('password-reset', RequestResetPasswordView.as_view(), name="password-reset"),
    path('password-reset-completion/<uidb64>/<token>', SetNewPasswordAPIView.as_view(), name='password-reset-completion')
]
