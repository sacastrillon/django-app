from django.contrib import admin
from django.urls import path, include
from core.views import LoginView, RegisterView, VerifyEmail

urlpatterns = [
    path('admin/', admin.site.urls),
    #path('auth/', include('djoser.urls')),
    path('signup/', RegisterView.as_view(), name='signup'),
    path('email-verify/', VerifyEmail.as_view(), name='email-verify'),
    path('login', LoginView.as_view(), name='login')

]
