from unittest import TestCase

from content_security_policy import directives
from content_security_policy.utils import kebab_to_pascal
from content_security_policy.constants import DIRECTIVE_NAMES


class DirectivesComplete(TestCase):
    def test_directives_complete(self):
        for name in DIRECTIVE_NAMES:
            with self.subTest(name):
                class_name = kebab_to_pascal(name)
                if not hasattr(directives, class_name):
                    self.fail(
                        f"directives has no class {class_name} for directive {name}"
                    )
