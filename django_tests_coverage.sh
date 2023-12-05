#!/usr/bin/env sh

. $(poetry env info --path)/bin/activate

coverage run --source content_security_policy/django/ \
 content_security_policy/django/manage.py test \
 content_security_policy/django/test/

coverage report