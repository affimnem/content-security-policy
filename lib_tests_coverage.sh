#!/usr/bin/env sh

. $(poetry env info --path)/bin/activate

coverage run --source content_security_policy \
-m unittest discover content_security_policy

coverage report