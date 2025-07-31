from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView

app_name = 'jwt_auth'

urlpatterns = [
    # Web interface URLs
    path('', views.jwt_auth_home, name='home'),
    path('login/', views.jwt_login, name='login'),
    path('register/', views.jwt_register, name='register'),
    path('logout/', views.jwt_logout, name='logout'),
    path('dashboard/', views.jwt_dashboard, name='dashboard'),
    path('profile/', views.jwt_profile, name='profile'),
    path('sessions/', views.jwt_session_management, name='session_management'),
    path('session/<uuid:session_id>/', views.jwt_session_detail, name='session_detail'),

    # API endpoints for JWT authentication
    path('api/login/', views.api_jwt_login, name='api_login'),
    path('api/logout/', views.api_jwt_logout, name='api_logout'),
    path('api/user/', views.api_jwt_user_profile, name='api_user_profile'),
    path('api/sessions/', views.api_jwt_sessions, name='api_sessions'),
    path('api/sessions/terminate/', views.api_jwt_terminate_session, name='api_terminate_session'),
    path('api/sessions/terminate-all/', views.api_jwt_terminate_all_sessions, name='api_terminate_all'),

    # DRF SimpleJWT endpoints
    path('api/token/', views.CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Status endpoint
    path('api/status/', views.jwt_auth_status, name='auth_status'),
]
