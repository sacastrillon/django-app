import jwt
from rest_framework import viewsets, generics, status
from rest_framework.generics import ListCreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import Token, RefreshToken
from rest_framework.response import Response
from django.core import serializers
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.http import HttpResponsePermanentRedirect

from .permissions import IsOwnerProfileOrReadOnly
from .models import User
from .serializer import UserRegistrationSerializer, ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer, LoginSerializer
from .utils import Utils

class RegisterView(generics.GenericAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes=[IsOwnerProfileOrReadOnly]

    def post(self, request):
        try:
            user = request.data
            serializer = self.serializer_class(data=user)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            user_data = serializer.data
            user = User.objects.get(email=user_data['email'])

            token = RefreshToken.for_user(user).access_token

            current_site = get_current_site(request).domain
            #relative_link = reverse('email-verify')        
            #absolute_url = "https://" + current_site + relative_link + "?token=" + str(token)
            absolute_url = "https://sacastrillon.com/accountVerify?token=" + str(token)            

            email_body = 'Hi ' + user.first_name + ',\nUse link below to verify your account: \n\n' + absolute_url

            data = {'to': user.email,
                    'subject': 'Verify account',
                    'body': email_body}
            Utils.send_email(data)
            return Response({'status': {'code': status.HTTP_200_OK, 'message': 'User registered successfully. An email has been sent for your account activation.'}}, status=status.HTTP_200_OK)        
        except Exception as e:
            if(str(e).__contains__("already exists")):
                return Response({'status': {'code':status.HTTP_400_BAD_REQUEST, 'message': 'Email already registered.'}}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'status': {'code':status.HTTP_400_BAD_REQUEST, 'message': 'Bad request.'}}, status=status.HTTP_400_BAD_REQUEST)

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
                return Response({'status': {'code': status.HTTP_200_OK, 'message': 'Account succesfully activated.'}}, status=status.HTTP_200_OK)
            else :
                return Response({'status': {'code': status.HTTP_401_UNAUTHORIZED, 'message': 'Account already activated.'}}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.ExpiredSignatureError:
            return Response({'status': {'code': status.HTTP_401_UNAUTHORIZED, 'message': 'Activation link expired.'}}, status=status.HTTP_401_UNAUTHORIZED)
        except jwt.exceptions.DecodeError:
            return Response({'status': {'code': status.HTTP_401_UNAUTHORIZED, 'message': 'Invalid token.'}}, status=status.HTTP_401_UNAUTHORIZED)

class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            return Response({'status': {'code': status.HTTP_200_OK, 'message': 'Successfully logged in.'},
            'data': serializer.validated_data}, status=status.HTTP_200_OK)
        except Exception:
            return Response({'status': {'code': status.HTTP_404_NOT_FOUND, 'message': 'User not found.'}}, status=status.HTTP_404_NOT_FOUND)

class RequestResetPasswordView(generics.GenericAPIView):
    permission_classes = [IsOwnerProfileOrReadOnly]
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        self.serializer_class(data=request.data)
        email = request.data.get('email', '')

        if not email is None and email != '':
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)

                current_site = get_current_site(request=request).domain
                #relativeLink = reverse('password-reset-completion', kwargs={'uidb64': uidb64, 'token': token})
                #absurl = 'https://' + current_site + relativeLink
                absurl = 'https://sacastrillon.com/resetPassword/' + uidb64 + "/" + token
                email_body = 'Hi ' + user.first_name + \
                    ', \nUse link below to reset your password  \n' + absurl

                data = {'to': user.email,
                        'subject': 'Reset Password',
                        'body': email_body}
                Utils.send_email(data)

                return Response({'status': {'code': status.HTTP_200_OK, 'message': 'An email has been sent successfully with reset password link.'}}, status=status.HTTP_200_OK)
            else:
                return Response({'status': {'code': status.HTTP_404_NOT_FOUND, 'message': 'Email does not found.'}}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'status': {'code':status.HTTP_400_BAD_REQUEST, 'message': 'Invalid email.'}}, status=status.HTTP_400_BAD_REQUEST)

class SetNewPasswordAPIView(generics.GenericAPIView):
    permission_classes=[IsOwnerProfileOrReadOnly]
    serializer_class = SetNewPasswordSerializer

    def post(self, request, uidb64, token):
        data = {
            'password': request.data['password'], 
            'token': token, 
            'uidb64': uidb64
        }
        try:
            serializer = self.serializer_class(data=data)
            serializer.is_valid(raise_exception=True)
            return Response({'status': {'code':status.HTTP_200_OK, 'message': 'Password reset successfully.'}}, status=status.HTTP_200_OK)
        except Exception:
            return Response({'status': {'code':status.HTTP_400_BAD_REQUEST, 'message': 'Bad request.'}}, status=status.HTTP_400_BAD_REQUEST)

        
