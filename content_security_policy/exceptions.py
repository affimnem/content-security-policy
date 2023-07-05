class BadCsp(Exception):
    ...


class BadSourceExpression(BadCsp):
    ...


class BadDirective(BadCsp):
    ...


class BadPolicy(BadCsp):
    ...
