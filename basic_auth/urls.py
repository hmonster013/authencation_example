from django.urls import path
from . import views

app_name = 'basic_auth'

urlpatterns = [
    path('', views.basic_auth_home, name='home'),
    path('login/', views.basic_login, name='login'),
    path('register/', views.basic_register, name='register'),
    path('logout/', views.basic_logout, name='logout'),
    path('dashboard/', views.basic_dashboard, name='dashboard'),
    path('profile/', views.basic_profile, name='profile'),
    path('api/status/', views.auth_status, name='auth_status'),
]
