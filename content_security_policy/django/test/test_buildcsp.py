from pathlib import Path
from tempfile import TemporaryDirectory

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from content_security_policy import Policy, PolicyList
from content_security_policy.directives import *
from content_security_policy.django.auto_src import AutoHostScriptSrc
from content_security_policy.django.constants import CSP_CONFIG_NAME, CSP_RO_CONFIG_NAME
from content_security_policy.django.management.commands import buildcsp
from content_security_policy.values import *


class BuildCSPTest(TestCase):
    @override_settings(
        **{
            CSP_CONFIG_NAME: [
                AutoHostScriptSrc(
                    *settings.EXTERNAL_SCRIPTS,
                    watch_apps=settings.INSTALLED_APPS,
                ),
            ]
        },
    )
    def test_fail_build(self):
        """
        Command should raise if AutoDirective has unspecified values.
        """
        with self.assertRaises(CommandError), TemporaryDirectory() as tmp_dir:
            csp_path = Path(tmp_dir) / "csp"
            call_command(buildcsp.Command(), path=csp_path)

    @override_settings(
        **{
            CSP_CONFIG_NAME: [
                AutoHostScriptSrc(
                    *settings.EXTERNAL_SCRIPTS,
                    watch_dirs=[Path(__file__).parent / "test_watch_dir"],
                    host="localhost",
                    scheme="http",
                ),
            ]
        },
    )
    def test_watch_dir(self):
        """
        Command should raise if AutoDirective has unspecified values.
        """
        expected_csp = PolicyList(
            Policy(
                ScriptSrc(
                    HostSrc("https://code.jquery.com/jquery-3.5.1.js"),
                    HostSrc("http://localhost/static/bundle.js"),
                    HostSrc("http://localhost/static/index.js"),
                )
            )
        )
        with TemporaryDirectory() as tmp_dir:
            csp_path = Path(tmp_dir) / "csp"
            call_command(buildcsp.Command(), path=csp_path)
            with open(csp_path) as f:
                rendered = f.read()
                self.assertEquals(rendered, str(expected_csp))

    @override_settings(
        **{
            CSP_CONFIG_NAME: [
                AutoHostScriptSrc(
                    *settings.EXTERNAL_SCRIPTS,
                    watch_apps=[
                        "content_security_policy.django",
                    ],
                    host="localhost",
                    scheme="http",
                ),
            ]
        },
    )
    def test_watch_apps(self):
        """
        Command should raise if AutoDirective has unspecified values.
        """
        expected_csp = PolicyList(
            Policy(
                ScriptSrc(
                    HostSrc("https://code.jquery.com/jquery-3.5.1.js"),
                    HostSrc("http://localhost/static/main.js"),
                    HostSrc("http://localhost/static/some-lib.js"),
                )
            )
        )
        with TemporaryDirectory() as tmp_dir:
            csp_path = Path(tmp_dir) / "csp"
            call_command(buildcsp.Command(), path=csp_path)
            with open(csp_path) as f:
                rendered = f.read()
                self.assertEquals(rendered, str(expected_csp))

    @override_settings(
        **{
            CSP_CONFIG_NAME: [
                ScriptSrcAttr(KeywordSource.self),
            ],
        },
    )
    def test_write_csp(self):
        """
        CSP must be written to file.
        """

        # We are not testing render here!
        expected_csp = buildcsp.Command().render()["csp"]

        with TemporaryDirectory() as tmp_dir:
            csp_path = Path(tmp_dir) / "csp"
            call_command(buildcsp.Command(), path=csp_path)
            with open(csp_path, "r") as f:
                file_contents = f.read()
            self.assertEquals(file_contents, str(expected_csp))

    @override_settings(
        **{
            CSP_CONFIG_NAME: None,
            CSP_RO_CONFIG_NAME: [
                ScriptSrc(KeywordSource.self),
            ],
        },
    )
    def test_write_ro_csp(self):
        """
        RO CSP must be written to file.
        """
        # We are not testing render here!
        expected_csp = buildcsp.Command().render()["csp_ro"]

        with TemporaryDirectory() as tmp_dir:
            csp_ro_path = Path(tmp_dir) / "csp_ro"
            call_command(buildcsp.Command(), path_ro=csp_ro_path)
            with open(csp_ro_path, "r") as f:
                file_ro_contents = f.read()
            self.assertEquals(file_ro_contents, str(expected_csp))

    @override_settings(
        **{
            CSP_CONFIG_NAME: [
                StyleSrc(KeywordSource.self),
            ],
            CSP_RO_CONFIG_NAME: [
                ScriptSrcAttr(KeywordSource.self),
            ],
        },
    )
    def test_write_both(self):
        """
        RO CSP must be written to file.
        """
        # We are not testing render here!
        expected_csps = buildcsp.Command().render()

        with TemporaryDirectory() as tmp_dir:
            csp_path = Path(tmp_dir) / "csp"
            csp_ro_path = Path(tmp_dir) / "csp_ro"
            call_command(buildcsp.Command(), path=csp_path, path_ro=csp_ro_path)

            with open(csp_path, "r") as f:
                file_contents = f.read()
            with open(csp_ro_path, "r") as f:
                file_ro_contents = f.read()

            self.assertEquals(file_contents, str(expected_csps["csp"]))
            self.assertEquals(file_ro_contents, str(expected_csps["csp_ro"]))
