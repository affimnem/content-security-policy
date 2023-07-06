# Handling Content-Security-Policy with less footguns

Create, maintain, parse and
manipulate [Content Security Policies](https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy).

## For site developers / operators

Content-Security-Policy (CSP) is a very effective mitigation against cross site scripting (XSS).
It should be right up there with HTTPS on your list of mitigations to deploy on your site. Depending on your
applicaiton, creating and maintaining a CSP can be somewhat frickle and annoying. This library hopes to alleviate that
pain by allowing you to create (or automate creating) your policy as code.

## For researchers

More and more features for parsing and analyzing are under construction right now.

# Priorities

## 1. Correctness

No guarantees, but the number one rule is:
> If you don't deliberately bypass any safeguards when constructing a CSP programmatically, the string you obtain from
> it will be according to spec.

Note that this does not mean your CSP will be _effective_! A `script-src` with `'unsafe-inline'` is correct according
to the spec, but you loose any XSS protection CSP could have provided you with!

## 2. Useful

Handling the objects created with this library should be reasonably intuitive and "pythonic".
