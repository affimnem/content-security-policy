from django.http import HttpResponse, HttpRequest


def simple_page(request: HttpRequest):
    return HttpResponse("Hello World")

