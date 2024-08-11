
from django.contrib import admin
from django.urls import path
from django.urls import path
from reg_app import views
from django.contrib.auth.views import PasswordResetView
from django.contrib.auth import views as auth_views
from django.urls import path
from reg_app import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('log_in/', views.login_view, name='LoginPage'),
    path('', views.sign_up_view, name='SignUpPage'),
    path('home/', views.homePage, name='HomePage'),
    path('logout/', views.logoutpage, name='LogoutPage'),
    path('forget_password/', views.forget_password_page, name='ForgetPasswordPage'),
    path('forget_password_result/', views.forget_password_result, name='ForgetPasswordResult'),
    path('reset/<uidb64>/<token>/', views.reset_password, name='reset_password'),
    path('forget_password_result/', views.forget_password_result, name='forget_password_result'),
    path('new_password/<uidb64>/<token>/', views.new_password, name='LoginPage_newpassword')
]
