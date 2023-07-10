class BadCsp(Exception):
    ...


class NoSuchDirective(BadCsp):
    ...


class BadDirectiveValue(BadCsp):
    ...


class BadSourceExpression(BadDirectiveValue):
    ...


class BadDirective(BadCsp):
    ...


class BadSourceList(BadDirective):
    ...


class BadPolicy(BadCsp):
    ...
