"""
URL configuration for resources app
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'accounts', views.AWSAccountViewSet)
router.register(r'vpcs', views.VPCViewSet)
router.register(r'subnets', views.SubnetViewSet)
router.register(r'security-groups', views.SecurityGroupViewSet)
router.register(r'enis', views.ENIViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
