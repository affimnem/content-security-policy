from unittest import TestCase

from content_security_policy import directives
from content_security_policy.constants import DIRECTIVE_NAMES
from content_security_policy.parse import _PARSING_RULES
from content_security_policy.utils import kebab_to_pascal


class DirectivesComplete(TestCase):
    def test_directives_complete(self):
        for name in DIRECTIVE_NAMES:
            with self.subTest(name):
                class_name = kebab_to_pascal(name)
                if not hasattr(directives, class_name):
                    self.fail(
                        f"directives has no class {class_name} for directive {name}"
                    )

    def test_directive_parsing_rules(self):
        """
        Every directive must be targeted by exactly one parsing rules.
        """
        for name in DIRECTIVE_NAMES:
            class_name = kebab_to_pascal(name)
            if clz := getattr(directives, class_name, None):
                with self.subTest(name):
                    matching_rules = sum(
                        issubclass(clz, d_type) for d_type in _PARSING_RULES
                    )
                    self.assertEqual(matching_rules, 1)
