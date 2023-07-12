from unittest import TestCase

from content_security_policy.parse import (
    directive_from_string,
    policy_from_string,
    policy_list_from_string,
)


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

    def test_parse_serialize_policy_list(self):
        as_string = "default-src 'self'; script-src 'nonce-ABCD'; frame-ancestors 'self'; upgrade-insecure-requests;"
        parsed = policy_list_from_string(as_string)
        self.assertEqual(as_string, str(parsed))

    def test_parse_serialize_messy_policy_list(self):
        as_string = "   \n require-trusted-types-for 'script';report-uri /_/somehing/cspreport, script-src 'report-sample' 'nonce-EmTYwW9IZXpvlIOURJMuAQ' 'unsafe-inline';object-src 'none';base-uri 'self';report-uri /_/something/cspreport;worker-src 'self' \t "
        parsed = policy_list_from_string(as_string)
        self.assertEqual(as_string, str(parsed))
