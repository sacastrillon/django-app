import jwt
from rest_framework import viewsets, generics, status
from rest_framework.generics import ListCreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenVerifySerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import Token, RefreshToken
from rest_framework.response import Response
from django.core import serializers
from django.forms.models import model_to_dict
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.http import HttpResponsePermanentRedirect

from .permissions import IsOwnerProfileOrReadOnly
from .models import User
from .serializer import UserRegistrationSerializer, ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer
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
            return Response({'success': 'Succesfully activated'}, status=status.HTTP_200_OK)
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

class RequestResetPasswordView(generics.GenericAPIView):
    permission_classes=[IsOwnerProfileOrReadOnly]
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data.get('email', '')

        if not email is None and email != '':
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                
                current_site = get_current_site(request=request).domain
                relativeLink = reverse(
                    'password-reset-completion', kwargs={'uidb64': uidb64, 'token': token})
                absurl = 'http://'+ current_site + relativeLink
                email_body = 'Hi ' + user.first_name + ', \nUse link below to reset your password  \n' + \
                    absurl
                data = {'body': email_body, 'to': user.email,
                        'subject': 'Reset your passsword'}
                Utils.send_email(data)
                
                return Response({'success': 'Email sent'}, status=status.HTTP_200_OK)
            else:        
                return Response({'error': 'Email does not exist.'}, status=status.HTTP_400_BAD_REQUEST)        
        else:
            return Response({'error': 'Invalid email.'}, status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordAPIView(generics.GenericAPIView):
    permission_classes=[IsOwnerProfileOrReadOnly]
    serializer_class = SetNewPasswordSerializer
    def post(self, request, uidb64, token):
        data = {
            'password': request.data['password'], 
            'token': token, 
            'uidb64': uidb64
        }
        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': 'Password reset successfully'}, status=status.HTTP_200_OK)