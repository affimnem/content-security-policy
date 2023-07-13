from unittest import TestCase
from typing import cast

from content_security_policy import *
from content_security_policy.exceptions import NoSuchDirective
from content_security_policy.parse import policy_from_string


class SimpleExample(TestCase):
    def test_simple_policy(self):
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        self.assertEqual(
            "default-src 'self'; frame-ancestors 'self'; object-src 'none'", str(policy)
        )

    def test_add_directive(self):
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        policy += StyleSrc(HostSrc("http://example.com"))
        self.assertEqual(
            "default-src 'self'; frame-ancestors 'self'; object-src 'none'; style-src http://example.com",
            str(policy),
        )

    def test_remove_directive(self):
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        policy -= FrameAncestors
        self.assertEqual(
            "default-src 'self'; object-src 'none'",
            str(policy),
        )

    def test_remove_preserve_whitespace(self):
        policy = policy_from_string(
            "default-src \t 'self'; \n frame-ancestors 'self'; \tobject-src 'none' ;\x0c\t style-src http://example.com"
        )
        policy -= FrameAncestors
        self.assertEqual(
            "default-src \t 'self'; \tobject-src 'none' ;\x0c\t style-src http://example.com",
            str(policy),
        )

    def test_complex_manipulation(self):
        policy = policy_from_string(
            "deFault-src 'self'; Frame-Ancestors\t 'self'; \t object-src 'none'"
        )

        frame_ancestors = policy["frame-ancestors"]
        # alternatively:
        # frame_ancestors = policy.frame_ancestors
        frame_ancestors += HostSrc("https://example.com")

        policy -= FrameAncestors
        policy += frame_ancestors

        self.assertEqual(
            "deFault-src 'self'; \t object-src 'none'; Frame-Ancestors\t 'self' https://example.com",
            str(policy),
        )

    def test_getitem_int(self):
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        self.assertEqual("default-src 'self'", str(policy[0]))

    def test_getitem_str_kebab(self):
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        self.assertEqual("frame-ancestors 'self'", str(policy["frame-ancestors"]))

    def test_getitem_str_pascal(self):
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        self.assertEqual("frame-ancestors 'self'", str(policy["FrameAncestors"]))

    def test_getitem_type(self):
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        self.assertEqual("object-src 'none'", str(policy[ObjectSrc]))

    def test_getitem_type_error(self):
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        with self.assertRaises(TypeError):
            key = cast(str, ValueItem)
            _ = policy[key]

    def test_getitem_no_such_directive(self):
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        with self.assertRaises(NoSuchDirective):
            _ = policy["does-not-exist"]

    def test_getitem_index_error(self):
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        with self.assertRaises(IndexError):
            _ = policy["style-src"]

    def test_getattr_snake(self):
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        self.assertEqual("object-src 'none'", str(policy.object_src))

    def test_getattr_Pascal(self):
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        self.assertEqual("object-src 'none'", str(policy.ObjectSrc))

    def test_getitem_attr_error_not_found(self):
        """
        Attribute error should be raised if the policy doesn't have such a directive.
        """
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        with self.assertRaises(AttributeError):
            _ = policy.style_src

    def test_getitem_attr_error_invalid(self):
        """
        Attribute error should be raised instead of NoSuchDirective.
        """
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        with self.assertRaises(AttributeError):
            _ = policy.nonexisting_directive
