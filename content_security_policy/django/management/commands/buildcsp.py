from argparse import ArgumentParser
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, List, Tuple

from django.conf import settings
from django.core.checks import Tags
from django.core.exceptions import ImproperlyConfigured
from django.core.files import File
from django.core.management.base import BaseCommand, CommandError

from content_security_policy import Policy, PolicyList
from content_security_policy.django.auto_src import AutoSrcDirective
from content_security_policy.django.constants import CSP_CONFIG_NAME, CSP_RO_CONFIG_NAME
from content_security_policy.django.exceptions import ValuesMissing
from content_security_policy.django.utils.settings import get_csp_setting

_CSP = "csp"
_CSP_RO = "csp_ro"

_NAME_OPT = "--name"
_NAME_RO_OPT = "--name_ro"


class Command(BaseCommand):
    help = (
        f"Build CSP based on {CSP_CONFIG_NAME} and {CSP_RO_CONFIG_NAME} settings "
        "and save them to plain text files."
    )
    requires_system_checks = [Tags.staticfiles]

    def add_arguments(self, parser: ArgumentParser):
        parser.add_argument(
            _NAME_OPT,
            default="csp",
            dest=f"{_CSP}_name",
            help="Staticfiles file name to use for CSP file.",
        )
        parser.add_argument(
            _NAME_RO_OPT,
            default="csp_ro",
            dest=f"{_CSP_RO}_name",
            help="Staticfiles file name to use for report-only CSP file.",
        )
        parser.add_argument(
            "--path",
            help="Write CSP to path instead of staticfiles storage. "
            f"{_NAME_OPT} will be ignored.",
            type=Path,
            default=None,
            dest=f"{_CSP}_path",
        )
        parser.add_argument(
            "--path_ro",
            help="Write report-only CSP to path instead of staticfiles storage. "
            f"{_NAME_RO_OPT} will be ignored.",
            type=Path,
            default=None,
            dest=f"{_CSP_RO}_path",
        )

    def render(self) -> Dict[str, PolicyList]:
        """
        Render csp settings into csp classes.
        Produce useful error messages if applicable
        """
        policy_lists = {
            name: get_csp_setting(config_name)
            for name, config_name in (
                (_CSP, CSP_CONFIG_NAME),
                (_CSP_RO, CSP_RO_CONFIG_NAME),
            )
            if getattr(settings, config_name, None)
        }

        if not policy_lists:
            raise ImproperlyConfigured(
                f"{self.__class__.__name__} called but neither {CSP_CONFIG_NAME} nor "
                f"{CSP_RO_CONFIG_NAME} found in settings."
            )

        errors: List[Tuple[AutoSrcDirective, ValuesMissing]] = []
        rendered_policy_lists = {}
        for policy_type, policies in policy_lists.items():
            rendered_policies = []
            for policy in policies:
                rendered_directives = []
                for directive in policy:
                    if isinstance(directive, AutoSrcDirective):
                        # Auto directives do not get any additional args when they are
                        # rendered through the buildcsp command.
                        # This is intentional, you are forced to have everything in
                        # one place.
                        try:
                            rendered_directives.append(directive.render())
                        except ValuesMissing as e:
                            errors.append((directive, e))
                    else:
                        rendered_directives.append(directive)
                rendered_policies.append(Policy(*rendered_directives))
            rendered_policy_lists[policy_type] = PolicyList(*rendered_policies)

        if errors:
            message = "Your CSP can not be rendered.\n"
            for directive, e in errors:
                miss_names = ", ".join(e.names)
                message += (
                    f"Directive {directive.name} is missing values "
                    f"for: {miss_names}.\n"
                )

            raise CommandError(message, returncode=-1)

        return rendered_policy_lists

    def handle(self, *args, **options):
        rendered_policy_lists = self.render()

        for name, policy_list in rendered_policy_lists.items():
            file_name = options[f"{name}_name"]
            path: Path = options[f"{name}_path"]

            if path:
                with open(path, "w") as f:
                    f.write(str(policy_list))
                self.stdout.write(f"Wrote {name} value to {path.absolute()}")
            else:
                # This import is here because otherwise you would need to configure
                # staticfiles even if you don't use it.
                from django.contrib.staticfiles.storage import staticfiles_storage

                with NamedTemporaryFile("w+") as tmp:
                    tmp.write(str(policy_list))
                    tmp.flush()
                    with File(tmp) as django_f:
                        if staticfiles_storage.exists(file_name):
                            self.stdout.write(
                                f"Deleting file {staticfiles_storage.path(file_name)}"
                            )
                            staticfiles_storage.delete(file_name)

                        staticfiles_storage.save(file_name, django_f)
                        self.stdout.write(
                            f"Saved CSP at {staticfiles_storage.path(file_name)}"
                        )
