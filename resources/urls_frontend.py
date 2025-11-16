"""
Frontend URL configuration for resources app
"""
from django.urls import path
from . import views_frontend, views_edl

urlpatterns = [
    # Authentication
    path('login/', views_frontend.login_view, name='login'),
    path('logout/', views_frontend.logout_view, name='logout'),
    path('profile/', views_frontend.profile_view, name='profile'),
    path('profile/regenerate-token/', views_frontend.regenerate_token_view, name='regenerate_token'),

    # Frontend views
    path('', views_frontend.accounts_view, name='accounts'),
    path('accounts/', views_frontend.accounts_view, name='accounts'),
    path('enis/', views_frontend.enis_view, name='enis'),
    path('enis/<int:eni_id>/', views_frontend.eni_detail_view, name='eni_detail'),
    path('ec2-instances/', views_frontend.ec2_instances_view, name='ec2_instances'),
    path('ec2-instances/<int:instance_id>/', views_frontend.ec2_instance_detail_view, name='ec2_instance_detail'),
    path('security-groups/', views_frontend.security_groups_view, name='security_groups'),
    path('security-groups/<int:sg_id>/', views_frontend.security_group_detail_view, name='security_group_detail'),

    # EDL endpoints
    path('edl/', views_edl.edl_summary, name='edl_summary'),
    path('edl/enis/', views_edl.edl_enis_by_tags, name='edl_enis_by_tags'),
    path('edl/enis/json/', views_edl.edl_enis_by_tags_json, name='edl_enis_by_tags_json'),
    path('edl/account/<str:account_id>/', views_edl.edl_account_ips, name='edl_account_ips'),
    path('edl/account/<str:account_id>/json/', views_edl.edl_account_json, name='edl_account_json'),
    path('edl/sg/<str:sg_id>/', views_edl.edl_security_group_ips, name='edl_security_group_ips'),
    path('edl/sg/<str:sg_id>/json/', views_edl.edl_security_group_json, name='edl_security_group_json'),

    # Account polling
    path('poll-account/', views_frontend.poll_account_view, name='poll_account'),
    path('bulk-poll-accounts/', views_frontend.bulk_poll_accounts_view, name='bulk_poll_accounts'),

    # API endpoints
    path('api/accounts/', views_frontend.api_accounts_json, name='api_accounts'),
    path('api/enis/', views_frontend.api_enis_json, name='api_enis'),
]
