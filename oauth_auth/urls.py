from django.urls import path, include
from . import views

app_name = 'oauth_auth'

urlpatterns = [
    # Web interface URLs
    path('', views.oauth_auth_home, name='home'),
    path('dashboard/', views.oauth_dashboard, name='dashboard'),
    path('profile/', views.oauth_profile, name='profile'),
    path('accounts/', views.oauth_account_management, name='account_management'),
    path('connections/', views.oauth_app_connections, name='app_connections'),
    path('session/<uuid:session_id>/', views.oauth_session_detail, name='session_detail'),
    path('logout/', views.oauth_logout, name='logout'),

    # API endpoints for OAuth management
    path('api/user/', views.api_oauth_user_profile, name='api_user_profile'),
    path('api/sessions/', views.api_oauth_sessions, name='api_sessions'),
    path('api/disconnect/', views.api_oauth_disconnect_account, name='api_disconnect'),
    path('api/sessions/end/', views.api_oauth_end_session, name='api_end_session'),
    path('api/sessions/end-all/', views.api_oauth_end_all_sessions, name='api_end_all'),

    # Status endpoint
    path('api/status/', views.oauth_auth_status, name='auth_status'),

    # Include allauth URLs for OAuth providers
    path('accounts/', include('allauth.urls')),
]
