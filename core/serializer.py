from rest_framework import serializers
from .models import User
from djoser.serializers import UserCreateSerializer as BaseUserRegistrationSerializer
from rest_framework import exceptions
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenVerifySerializer
from django.forms.models import model_to_dict
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

class UserRegistrationSerializer(BaseUserRegistrationSerializer):
    class Meta(BaseUserRegistrationSerializer.Meta):
        model = User
        fields = ('first_name', 'last_name', 'email', 'password')


class LoginSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        try:
            data = super().validate(attrs)
            del data["access"]
            del data["refresh"]
            refresh = self.get_token(self.user)
            data['user'] = model_to_dict(self.user, fields=('email','first_name', 'last_name', 'date_joined'))
            data['token'] = str(refresh.access_token)
            return data
        except Exception:
            raise exceptions.NotFound('User not found.', 404)
        return super().validate(attrs)

class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)
    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, style={'input_type': 'password'})
    
    class Meta:
        fields = ('password', 'uidb64', 'token')

    def validate(self, attrs):
        try:
            password = self.initial_data['password']
            token = self.initial_data['token']
            uidb64 = self.initial_data['uidb64']

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise exceptions.AuthenticationFailed('Invalid reset password link.', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception:
            raise exceptions.AuthenticationFailed('Invalid reset password link.', 401)
        return super().validate(attrs)