# Handling Content-Security-Policy with less footguns

Create, maintain, parse and
manipulate [Content Security Policies](https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy).

## For site developers / operators

Content-Security-Policy (CSP) is a very effective mitigation against cross site scripting (XSS).
It should be right up there with HTTPS on your list of mitigations to deploy on your site. Depending on your
applicaiton, creating and maintaining a CSP can be somewhat frickle and annoying. This library hopes to alleviate that
pain by allowing you to create (or automate creating) your policy as code.

## For researchers

Features for parsing and analyzing are under construction right now.

# Principles

## Immutability

Any policy / directive / directive value object you create is immutable.

## Strict construction

> :warning: This feature is still under construction! There are a lot of things not yet being validated.

When explicitly constructing objects with invalid values, errors will be raised! For example, you can not construct a
nonce source expression with characters non-base64 characters.

```
>>> NonceSrc("ungültig")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "<redacted>/content_security_policy/values.py", line 55, in __init__
    raise BadSourceExpression(
content_security_policy.exceptions.BadSourceExpression: Nonce value 'ungültig' does not match ([A-Za-z]|[0-9]|[+\/\-_]){2, 0}={0, 2}
```

## Lenient parsing

> :information_source: Parsing features are under construction.

# Usage

There is are classes for policy, different kinds of directives and directive values. For now, you will need to check
the source code / rely on auto-completion for the available classes. The general idea is hopefully well conveyed in
these examples:

### Something very simple:

```python
from content_security_policy import *

policy = Policy(
    DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
)
assert str(policy) == "default-src 'self'; frame-ancestors 'self'; object-src 'none'"
```

### Something a little more dynamic:

```python
from content_security_policy import *

script_src = ScriptSrc()

for url in ["https://example.com/some-lib.js", "https://example-cdn.com/other-lib.js"]:
    script_src += HostSrc(url)

script_src += SelfSrc

assert str(script_src) == "script-src https://example.com/some-lib.js https://example-cdn.com/other-lib.js 'self'"
```

# Priorities

## 1. Correctness

No guarantees, but the number one rule is:
> If you don't deliberately bypass any safeguards when constructing a CSP programmatically, the string you obtain from
> it will be according to spec.

Note that this does not mean your CSP will be _effective_! A `script-src` with `'unsafe-inline'` is correct according
to the spec, but you loose any XSS protection CSP could have provided you with!

## 2. Useful

Handling the objects created with this library should be reasonably intuitive and "pythonic".
