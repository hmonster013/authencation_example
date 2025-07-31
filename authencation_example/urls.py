"""
URL configuration for authencation_example project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

def home_redirect(request):
    return redirect('basic_auth:home')

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", home_redirect, name="home"),
    path("basic/", include("basic_auth.urls")),
    path("jwt/", include("jwt_auth.urls")),
    path("oauth/", include("oauth_auth.urls")),
    path("token/", include("token_auth.urls")),
    path("cookie/", include("cookie_auth.urls")),
    path("accounts/", include("allauth.urls")),
]
