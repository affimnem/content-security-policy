from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.test import Client, SimpleTestCase, override_settings

from content_security_policy.constants import CSP_HEADER, CSP_RO_HEADER
from content_security_policy.directives import *
from content_security_policy.django.auto_src import AutoHostScriptSrc
from content_security_policy.django.constants import CSP_CONFIG_NAME, CSP_RO_CONFIG_NAME
from content_security_policy.django.middleware import AutoCSPMiddleware
from content_security_policy.values import *

TEST_CSP_SETTING = [
    AutoHostScriptSrc(
        *settings.EXTERNAL_SCRIPTS,
        watch_apps=settings.INSTALLED_APPS,
    ),
    ScriptSrcAttr(NoneSrc),
    DefaultSrc(KeywordSource.self),
    StyleSrc(KeywordSource.self),
    FrameAncestors(NoneSrc),
    BaseUri(NoneSrc),
    ObjectSrc(NoneSrc),
    ManifestSrc(NoneSrc),
]

TEST_CSP_RO_SETTING = [
    ScriptSrcAttr(KeywordSource.self),
    DefaultSrc(KeywordSource.self),
    StyleSrc(KeywordSource.self),
]


class AutoCSPMiddlewareTests(SimpleTestCase):
    def test_no_debug(self):
        """
        Tests set DEBUG=False by default, the middleware must raise.
        """
        with self.assertRaises(ImproperlyConfigured):
            self.client.get("/")

    @override_settings(DEBUG=True)
    def test_no_host_header(self):
        """
        The middleware uses the host header to construct source expressions.
        Return 400 if it is not set.
        """
        response = self.client.get("/")
        self.assertEquals(response.status_code, 400)

    @override_settings(
        DEBUG=True,
        **{
            CSP_CONFIG_NAME: TEST_CSP_SETTING,
        },
    )
    def test_csp_inject(self):
        """
        CSP header needs to be injected.
        This test is ONLY for the injection mechanism, not for rendering.
        """
        expected_csp = AutoCSPMiddleware.render(
            [TEST_CSP_SETTING],
            scheme="http",
            host="testserver",
        )
        client = Client(HTTP_HOST="testserver")
        response = client.get("/")
        self.assertEquals(response.headers[CSP_HEADER], str(expected_csp))

    @override_settings(
        DEBUG=True,
        **{
            CSP_RO_CONFIG_NAME: TEST_CSP_RO_SETTING,
        },
    )
    def test_csp_ro_inject(self):
        """
        CSP RO header needs to be injected.
        This test is ONLY for the injection mechanism, not for rendering.
        """
        expected_csp_ro = AutoCSPMiddleware.render(
            [TEST_CSP_RO_SETTING],
            scheme="http",
            host="testserver",
        )
        client = Client(HTTP_HOST="testserver")
        response = client.get("/")
        self.assertEquals(response.headers[CSP_RO_HEADER], str(expected_csp_ro))

    @override_settings(
        DEBUG=True,
        **{
            CSP_CONFIG_NAME: TEST_CSP_SETTING,
            CSP_RO_CONFIG_NAME: TEST_CSP_RO_SETTING,
        },
    )
    def test_csp_both_inject(self):
        """
        Both CSP headers needs to be injected.
        This test is ONLY for the injection mechanism, not for rendering.
        """
        expected_csp = AutoCSPMiddleware.render(
            [TEST_CSP_SETTING],
            scheme="http",
            host="testserver",
        )
        expected_csp_ro = AutoCSPMiddleware.render(
            [TEST_CSP_RO_SETTING],
            scheme="http",
            host="testserver",
        )
        client = Client(HTTP_HOST="testserver")
        response = client.get("/")
        self.assertEquals(response.headers[CSP_HEADER], str(expected_csp))
        self.assertEquals(response.headers[CSP_RO_HEADER], str(expected_csp_ro))
