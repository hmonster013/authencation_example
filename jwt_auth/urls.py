from django.urls import path
from django.http import HttpResponse

def placeholder_view(request):
    return HttpResponse("JWT Authentication - Coming Soon!")

app_name = 'jwt_auth'

urlpatterns = [
    path('', placeholder_view, name='home'),
]
