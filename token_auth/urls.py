from django.urls import path
from . import views

app_name = 'token_auth'

urlpatterns = [
    # Web interface URLs
    path('', views.token_auth_home, name='home'),
    path('login/', views.token_login, name='login'),
    path('register/', views.token_register, name='register'),
    path('logout/', views.token_logout, name='logout'),
    path('dashboard/', views.token_dashboard, name='dashboard'),
    path('profile/', views.token_profile, name='profile'),
    path('management/', views.token_management, name='token_management'),
    path('token/<int:token_id>/', views.token_detail, name='token_detail'),

    # API endpoints for token authentication
    path('api/user/', views.api_user_profile, name='api_user_profile'),
    path('api/token/info/', views.api_token_info, name='api_token_info'),
    path('api/token/create/', views.api_create_token, name='api_create_token'),
    path('api/token/refresh/', views.api_refresh_token, name='api_refresh_token'),
    path('api/token/revoke/', views.api_revoke_token, name='api_revoke_token'),

    # Status endpoint
    path('api/status/', views.token_auth_status, name='auth_status'),
]
