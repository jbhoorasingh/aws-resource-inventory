"""
Frontend URL configuration for resources app
"""
from django.urls import path
from . import views_frontend, views_edl

urlpatterns = [
    path('', views_frontend.accounts_view, name='accounts'),
    path('accounts/', views_frontend.accounts_view, name='accounts'),
    path('enis/', views_frontend.enis_view, name='enis'),
    path('ec2-instances/', views_frontend.ec2_instances_view, name='ec2_instances'),
    path('ec2-instances/<int:instance_id>/', views_frontend.ec2_instance_detail_view, name='ec2_instance_detail'),
    path('security-groups/', views_frontend.security_groups_view, name='security_groups'),
    path('security-groups/<int:sg_id>/', views_frontend.security_group_detail_view, name='security_group_detail'),
    path('edl/', views_edl.edl_summary, name='edl_summary'),
    path('edl/account/<str:account_id>/', views_edl.edl_account_ips, name='edl_account_ips'),
    path('edl/account/<str:account_id>/json/', views_edl.edl_account_json, name='edl_account_json'),
    path('edl/sg/<str:sg_id>/', views_edl.edl_security_group_ips, name='edl_security_group_ips'),
    path('edl/sg/<str:sg_id>/json/', views_edl.edl_security_group_json, name='edl_security_group_json'),
    path('poll-account/', views_frontend.poll_account_view, name='poll_account'),
    path('api/accounts/', views_frontend.api_accounts_json, name='api_accounts'),
    path('api/enis/', views_frontend.api_enis_json, name='api_enis'),
]
