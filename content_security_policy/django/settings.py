"""
Django settings for content_security_policy.django project.
"""

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-t-3nx1^9ves=v(0+2sg)#lo3u^6m&)7pydi-vnf(8z)2s7x0lg"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "content_security_policy.django",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "content_security_policy.django.middleware.AutoCSPMiddleware",
]

ROOT_URLCONF = "content_security_policy.django.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "content_security_policy.django.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


from content_security_policy.directives import *
from content_security_policy.values import *
from content_security_policy.django.auto_src import AutoHostScriptSrc


EXTERNAL_SCRIPTS = [HostSrc("https://code.jquery.com/jquery-3.5.1.js")]

CONTENT_SECURITY_POLICY = [
    AutoHostScriptSrc(*EXTERNAL_SCRIPTS, watch_apps=INSTALLED_APPS),
    ScriptSrcAttr(NoneSrc),
    DefaultSrc(KeywordSource.self),
    StyleSrc(KeywordSource.self),
    FrameAncestors(NoneSrc),
    BaseUri(NoneSrc),
    ObjectSrc(NoneSrc),
    ManifestSrc(NoneSrc),
]
