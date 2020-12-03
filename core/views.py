from rest_framework import viewsets
from django.core import serializers
from rest_framework.generics import ListCreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from django.forms.models import model_to_dict

from .permissions import IsOwnerProfileOrReadOnly
from .models import User
from .serializer import UserRegistrationSerializer


class UserProfileListCreateView(ListCreateAPIView):
    queryset=User.objects.all()
    serializer_class=UserRegistrationSerializer
    permission_classes=[IsOwnerProfileOrReadOnly,IsAuthenticated]


class LoginSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        del data["access"]
        del data["refresh"]
        refresh = self.get_token(self.user)
        data['user'] = model_to_dict(self.user, fields=('email','first_name', 'last_name', 'date_joined'))
        data['token'] = str(refresh.access_token)
        return data


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer

