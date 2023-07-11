from unittest import TestCase

from content_security_policy.parse import directive_from_string


class DirectiveParsing(TestCase):
    def test_parse_serialize(self):
        as_string = "sCript-SrC 'self'\t'nonce-FOOBAR'\nhttp://example.com"
        parsed = directive_from_string(as_string)
        self.assertEqual(as_string, str(parsed))
