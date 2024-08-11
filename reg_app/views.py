from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import PasswordResetForm
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth import get_user_model



# Generate the password reset link


@login_required(login_url='LoginPage')
def homePage(request):
    return render(request,'home.html')

def  sign_up_view(request):
    if request.method=='POST':
        u_name=request.POST.get('username')
        u_email=request.POST.get('email')
        u_pass=request.POST.get('password')
        user_name=User.objects.filter(username=u_name)
        u_email=User.objects.filter(email=u_email)

        if user_name.exists():
            return render(request,'sin_up.html',{'error':'User is also exist with this name'})
        if u_email.exists():
            return render(request,'sin_up.html',{'error':'User is also exist with this email'})
        u_conf_pass=request.POST.get('c_password')
        u_email=request.POST.get('email')
        if u_pass==u_conf_pass:
            my_user=User.objects.create_user(u_name,u_email,u_pass)
            my_user.set_password(u_pass)
            my_user.save()
            return redirect('LoginPage')
        else:
            return render(request,'sin_up.html',{'error':'password not matched'})
    else:
        return render(request,'sin_up.html')

        


def login_view(request):
    if request.method == 'POST':
        u_name = request.POST.get('username')
        password = request.POST.get('password')
        
        # Authenticate the user
        user = authenticate(request, username=u_name, password=password)
        
        if user is not None:
            # If the user is authenticated successfully, log them in
            login(request, user)
            return redirect('HomePage')
        else:
            # If authentication fails, return an error message
            return render(request, 'log_in.html', {'error': 'Incorrect username or password'})
    
    # If the request method is not POST, just render the login page
    return render(request, 'log_in.html')
        


def logoutpage(request):
    logout(request)
    return redirect('LoginPage')

def forget_password_page(request):
    return render(request,'forget_pass.html')

def forget_password_result(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()

            
        if user:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            url=reverse('reset_password',kwargs={'uidb64':uid,'token':token})
            reset_url = f"http://127.0.0.1:8000{url}"
            send_mail(
                'Password Reset Request',
                f'Click the link below to reset your password: {reset_url}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False
            )
            messages.success(request, 'Password reset link sent to your email.')
            return redirect('ForgetPasswordPage')
        else:
            messages.error(request, 'No user found with this email.')
            return redirect('ForgetPasswordPage')

    return render(request, 'forget_pass.html')

"""def forget_password_result(request, uidb64, token):
    try:
        # Decode the user ID from uidb64
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    # Check if the token is valid
    if user is not None and default_token_generator.check_token(user, token):
        # Process the password reset form
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            if new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                messages.success(request, 'Your password has been reset successfully.')
                return redirect('LoginPage')
            else:
                messages.error(request, 'Passwords do not match.')
        return render(request, 'reset_pass.html', {'validlink': True})
    else:
        messages.error(request, 'The password reset link is invalid.')
        return redirect('ForgetPasswordPage')
"""                
"""def reset_password(request):
    return render(request,'reset_pass.html')"""

def reset_password(request, uidb64, token):
    try:
        # Decode the user's ID
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
        # Check if the token is valid
        if default_token_generator.check_token(user, token):
            # Token is valid, proceed with resetting the password
            # Here you can render a form or directly reset the password
            return render(request, 'reset_pass.html', {'uidb64': uidb64, 'token': token})
        else:
            return render(request, 'reset_pass.html', {'error': 'Invalid token.'})

    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
        return render(request, 'reset_pass.html', {'error': 'Invalid token.'})
    
    
def new_password(request, uidb64, token):
    try:
        # Decode the user's ID
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        
        # Check if the token is valid
        if default_token_generator.check_token(user, token):
            if request.method == 'POST':
                new_pass = request.POST.get('new_password')
                confirm_pass = request.POST.get('c_password')

                if new_pass == confirm_pass:
                    user.set_password(new_pass)  # Set the new password
                    user.save()  # Save the new password
                    messages.success(request, 'Password reset successful.')
                    return redirect('LoginPage')
                else:
                    return render(request, 'reset_pass.html', {'error': 'Passwords do not match.'})
            return render(request, 'reset_pass.html', {'error': 'Anonymous user.'})
        else:
            return render(request, 'reset_pass.html', {'error': 'Invalid token or token expired.'})

    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return render(request, 'reset_pass.html', {'error': 'Invalid token or user.'})
