from django.urls import path
from django.http import HttpResponse

def placeholder_view(request):
    return HttpResponse("OAuth Authentication - Coming Soon!")

app_name = 'oauth_auth'

urlpatterns = [
    path('', placeholder_view, name='home'),
]
