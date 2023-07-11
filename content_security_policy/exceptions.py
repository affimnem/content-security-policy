class CSPError(Exception):
    ...


class NoSuchDirective(CSPError):
    ...


class BadDirectiveValue(CSPError):
    ...


class BadSourceExpression(BadDirectiveValue):
    ...


class BadDirective(CSPError):
    ...


class BadSourceList(BadDirective):
    ...


class BadPolicy(CSPError):
    ...


class ParsingError(CSPError):
    ...
