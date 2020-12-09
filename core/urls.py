from django.urls import path
from .views import LoginView, RegisterView, VerifyEmail

urlpatterns = [
    path('signup', RegisterView.as_view(), name='signup'),
    path('email-verify', VerifyEmail.as_view(), name='email-verify'),
    path('login', LoginView.as_view(), name='login')
]
