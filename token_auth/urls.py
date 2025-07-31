from django.urls import path
from django.http import HttpResponse

def placeholder_view(request):
    return HttpResponse("Token Authentication - Coming Soon!")

app_name = 'token_auth'

urlpatterns = [
    path('', placeholder_view, name='home'),
]
