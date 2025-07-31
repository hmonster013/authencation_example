from django.urls import path
from . import views

app_name = 'cookie_auth'

urlpatterns = [
    path('', views.cookie_auth_home, name='home'),
    path('login/', views.cookie_login, name='login'),
    path('register/', views.cookie_register, name='register'),
    path('logout/', views.cookie_logout, name='logout'),
    path('dashboard/', views.cookie_dashboard, name='dashboard'),
    path('profile/', views.cookie_profile, name='profile'),
    path('settings/', views.cookie_settings, name='cookie_settings'),
    path('api/status/', views.cookie_auth_status, name='auth_status'),
]
