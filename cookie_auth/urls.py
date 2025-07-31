from django.urls import path
from django.http import HttpResponse

def placeholder_view(request):
    return HttpResponse("Cookie Authentication - Coming Soon!")

app_name = 'cookie_auth'

urlpatterns = [
    path('', placeholder_view, name='home'),
]
