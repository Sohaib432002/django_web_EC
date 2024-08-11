from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    #path('accounts/', include('django.contrib.auth.urls')),  # This includes the password reset views
    path('', include('reg_app.urls')),
    path('accounts/',include('allauth.urls'))
]
