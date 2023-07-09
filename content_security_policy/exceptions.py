class BadCsp(Exception):
    ...


class BadDirectiveValue(BadCsp):
    ...


class BadSourceExpression(BadDirectiveValue):
    ...


class BadSourceList(BadDirectiveValue):
    ...


class BadDirective(BadCsp):
    ...


class BadPolicy(BadCsp):
    ...
