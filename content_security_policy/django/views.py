from django.http import HttpRequest, HttpResponse


def simple_page(request: HttpRequest):
    return HttpResponse("Hello World")
