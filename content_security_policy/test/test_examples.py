from unittest import TestCase

from content_security_policy import *

# Here we just collect examples that broke for one reason or another to avoid
# regressions regarding functionality or typing


class TrustedTypesExampleTests(TestCase):
    def test_ex1(self):
        tt = Policy(
            RequireTrustedTypesFor(TrustedTypesSinkGroup.script),
            TrustedTypes(
                TrustedTypesPolicyName("default"),
                TrustedTypesWildcard,
                TrustedTypesKeyword.allow_duplicates,
            ),
        )
        self.assertEqual(
            str(tt),
            "require-trusted-types-for 'script'; trusted-types default * "
            "'allow-duplicates'",
        )
