from django.db import IntegrityError
from django.shortcuts import render, redirect
from django.views import View
import json
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.core.validators import validate_email
from django.contrib import messages, auth
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from .utils import account_activation_token

class EmailValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        email = data['email']
        if not validate_email(email):
            return JsonResponse({'email_error': 'Email is invalid'}, status=400)
        if User.objects.filter(email=email).exists():
            return JsonResponse({'email_error': 'sorry email in use,choose another one '}, status=409)
        return JsonResponse({'email_valid': True})


class UsernameValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        username = data['username']
        if not str(username).isalnum():
            return JsonResponse({'username_error': 'username should only contain alphanumeric characters'}, status=400)
        if User.objects.filter(username=username).exists():
            return JsonResponse({'username_error': 'sorry username in use,choose another one '}, status=409)
        return JsonResponse({'username_valid': True})


class RegistrationView(View):
    def get(self, request):
        return render(request, 'authentication/register.html')

    def post(self, request):
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        context = {'fieldValues': request.POST}

        try:
            User.objects.get(email=email)
            messages.error(request, 'Email already registered')
            return render(request, 'authentication/register.html', context)
        except User.DoesNotExist:
            pass

        if len(password) < 6:
            messages.error(request, 'Password too short')
            return render(request, 'authentication/register.html', context)

        try:
            user = User.objects.create_user(username=username, email=email, password=password)
            user.is_active = True  # User is active immediately after registration
            user.save()

            messages.success(request, 'Account successfully created.')
            return render(request, 'authentication/register.html')
        except IntegrityError:
            # Integrity error for a username already in use
            messages.error(request, 'Username already taken. Please choose another username.')
            return render(request, 'authentication/register.html', context)

class VerificationView(View):
    def get(self, request, uidb64, token):
        try:
            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=id)

            if not account_activation_token.check_token(user, token):
                return redirect('login'+'?message='+'User already activated')

            if user.is_active:
                return redirect('login')
            user.is_active = True
            user.save()

            messages.success(request, 'Account activated successfully')
            return redirect('login')

        except Exception as ex:
            pass

        return redirect('login')


class LoginView(View):
    def get(self, request):
        return render(request, 'authentication/login.html')

    def post(self, request):
        username = request.POST['username']
        password = request.POST['password']

        if username and password:
            user = auth.authenticate(username=username, password=password)
            if user:
                if user.is_active:
                    auth.login(request, user)
                    messages.success(request, f'Welcome {user.username}, you are now logged in')
                    return redirect('expenses')
            else:
                messages.error(request, 'Invalid credentials, try again')
        else:
            messages.error(request, 'Please fill all fields')

        return render(request, 'authentication/login.html')

class LogoutView(View):
    def post(self, request):
        auth.logout(request)
        messages.success(request, 'You have been logged out')
        return redirect('login')
