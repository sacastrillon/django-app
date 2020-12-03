from django.contrib import admin
from django.urls import path, include
from core.views import LoginView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('djoser.urls')),
    path('login', LoginView.as_view(), name='login')
]
