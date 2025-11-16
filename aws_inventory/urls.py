"""
URL configuration for aws_inventory project.
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('resources.urls')),
    path('api/auth/token/', obtain_auth_token, name='api_token_auth'),
    path('', include('resources.urls_frontend')),
]
