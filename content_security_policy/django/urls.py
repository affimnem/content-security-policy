from django.urls import path

from content_security_policy.django.views import simple_page

urlpatterns = [
    path("", simple_page),
]
