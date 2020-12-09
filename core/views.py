import jwt
from rest_framework import viewsets, generics, status
from rest_framework.generics import ListCreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from django.core import serializers
from django.forms.models import model_to_dict
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings

from .permissions import IsOwnerProfileOrReadOnly
from .models import User
from .serializer import UserRegistrationSerializer
from .utils import Utils

class UserProfileListCreateView(ListCreateAPIView):
    queryset=User.objects.all()
    serializer_class=UserRegistrationSerializer
    permission_classes=[IsOwnerProfileOrReadOnly,IsAuthenticated]


class RegisterView(generics.GenericAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes=[IsOwnerProfileOrReadOnly]
    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relative_link = reverse('email-verify')        
        absolute_url = "http://" + current_site + relative_link + "?token=" + str(token)

        email_body = 'Hi dear ' + user.first_name + ',\nUse link below to verify your account: \n\n' + absolute_url

        data = {'to': user.email,
                'subject': 'Verify account',
                'body': email_body}
        Utils.send_email(data)

        return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyEmail(generics.GenericAPIView):
    permission_classes=[IsOwnerProfileOrReadOnly]
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            if(not user.is_active):
                user.is_active = True
                user.save()
            return Response({'email': 'Succesfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation link expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


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

