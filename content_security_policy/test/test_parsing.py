from unittest import TestCase

from content_security_policy import RequireTrustedTypesFor, TrustedTypesSinkGroup
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


class Delimiters(TestCase):
    def test_trailing_delimiters(self):
        for as_string in [
            "default-src 'none'; ",
            "default-src 'none';",
            "default-src 'none'",
        ]:
            with self.subTest(as_string):
                parsed = policy_list_from_string(as_string)
                self.assertEqual(len(parsed), 1)
                policy = parsed[0]
                self.assertEqual(len(policy), 1)
                self.assertEqual(as_string, str(parsed))

    def test_empty_directive(self):
        as_string = "require-trusted-types-for"
        parsed = policy_list_from_string(as_string)
        self.assertEqual(len(parsed), 1)
        policy = parsed[0]
        self.assertEqual(len(policy), 1)
        self.assertEqual(as_string, str(parsed))


class Sandbox(TestCase):
    def test_parse_sandbox(self):
        as_string = "sandbox allow-popups allow-scripts;"
        parsed = policy_list_from_string(as_string)

        self.assertEqual(as_string, str(parsed))


class TrustedTypes(TestCase):
    def test_parse_trusted_types(self):
        as_string = "trusted-types pol1 pol-3 'allow-duplicates';"
        parsed = policy_list_from_string(as_string)
        self.assertEqual(as_string, str(parsed))

    def test_parse_require_trusted_types_for(self):
        as_string = "require-trusted-types-for 'script'"
        parsed = policy_list_from_string(as_string)
        self.assertEqual(len(parsed), 1)
        policy = parsed[0]
        self.assertEqual(len(policy), 1)
        directive = policy[RequireTrustedTypesFor]
        self.assertEqual(len(directive.values), 1)
        value = directive.values[0]
        self.assertTrue(isinstance(value, TrustedTypesSinkGroup))
        self.assertEqual(str(value), "'script'")
        self.assertEqual(as_string, str(parsed))
