from unittest import TestCase

from content_security_policy.parse import directive_from_string, policy_from_string


class DirectiveParsing(TestCase):
    def test_parse_serialize_directive(self):
        as_string = "sCript-SrC 'self'\t'nonce-FOOBAR'\nhttp://example.com"
        parsed = directive_from_string(as_string)
        self.assertEqual(as_string, str(parsed))

    def test_parse_serialize_policy(self):
        as_string = (
            "default-src https:; script-src\thttps:\x0c'unsafe-inline' \x0c  'unsafe-eval' blob: 'unsafe-inline'; "
            "frame-src https:   data:; style-src\nhttps: 'unsafe-inline'; img-src https: data: blob:; media-src https: "
            "data: blob:; \tfont-src https: data:;cconnect-src https: wss: blob:; child-src https: blob:; object-src "
            "'none'; base-uri https://*.example.com"
        )
        parsed = policy_from_string(as_string)
        self.assertEqual(as_string, str(parsed))
