class BadCsp(Exception):
    ...


class BadSourceExpression(BadCsp):
    ...


class BadSourceList(BadCsp):
    ...


class BadDirective(BadCsp):
    ...


class BadPolicy(BadCsp):
    ...
