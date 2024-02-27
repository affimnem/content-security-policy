from abc import ABCMeta, abstractmethod
from functools import cache
from pathlib import Path
from typing import *

from django.apps import apps
from django.templatetags.static import static
from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)

from content_security_policy import ValueItemType
from content_security_policy.directives import Directive
from content_security_policy.django.exceptions import ValuesMissing
from content_security_policy.values import HostSrc, SourceExpression

SRC_HASH_FUN = "sha384"


def fill_render_args(*argnames: str, optional: List[str] | None = None):
    """
    Decorator that overrides kwargs for render with equally named instance attributes.
    """

    def decorator(render_func: Callable) -> Callable:
        def wrapped_render(self: AutoSrcDirective, *args, **kwargs):
            missing = []
            for arg in argnames:
                on_self = getattr(self, arg)
                in_args = kwargs.get(arg)
                if on_self is None and in_args is None:
                    missing.append(arg)
                kwargs[arg] = on_self or in_args

            if optional is not None:
                for arg in optional:
                    kwargs[arg] = kwargs.get(arg) or getattr(self, arg)

            if missing:
                raise ValuesMissing(
                    f"Attempted to render a {self.name}, but some value(s) "
                    "where neither found on the policies attributes nor in the "
                    f"render arguments: {', '.join(missing)}",
                    names=missing,
                )

            return render_func(self, *args, **kwargs)

        return wrapped_render

    return decorator


def init_before_first_render(render_func):
    """
    Calls self.init_files before the first execution of render_func.
    Use it to call init_files before the first run of render.
    """

    def new_render(self, **kwargs):
        try:
            self.files_initialized
        except AttributeError:
            self.init_files()
            self.files_initialized = True
        return render_func(self, **kwargs)

    return new_render


DirectiveType = TypeVar("DirectiveType", bound=Directive)

# This is not bound to ValueItem, because you may have to defer creating an actual
# ValueItem until render
IntermediateValueType = TypeVar("IntermediateValueType")


class AutoSrcDirective(
    FileSystemEventHandler,
    Generic[DirectiveType, IntermediateValueType],
    metaclass=ABCMeta,
):
    """
    Automatically generates a -src directive from a list of source static_values and
    files in watch_dirs. Subclasses need to provide:
    - a directive class
    - a suffix (file extension) that will be "watched"
    - a method to compute a directive value that allow-lists a file in watch_dirs
      whenever it changes: compute_value_item
    """

    @property
    @abstractmethod
    def suffix(self) -> str:
        """
        Suffix (file extension) of the type of file that the directive watches for.
        """
        ...

    @property
    @abstractmethod
    def directive(self) -> Type[DirectiveType]:
        """
        Directive class to render.
        """
        ...

    @abstractmethod
    def compute_value_item(self, path: Path) -> IntermediateValueType:
        """
        Compute a directive value item to allow-list a local file.
        """
        ...

    def __init__(
        self,
        *static_values: SourceExpression,
        use_self_keyword: bool = False,
        watch_dirs: List[Path | str] | None = None,
        watch_apps: List[str] | None = None,
    ):
        self.static_values = static_values
        self.use_self_keyword = use_self_keyword
        self._watch_dirs = [Path(d) for d in watch_dirs] if watch_dirs else []
        self._watch_apps = watch_apps or []

        # Computing values for files is deferred until the first render,
        # because you might need django to be fully started up to compute anything
        # E.g.: AutoHostSrc calls django.templatetags.static.static, which can only be
        # called once django is fully up. See self.init_files.
        self.files: Dict[Path, IntermediateValueType] = {}

    @property
    def name(self):
        """
        Return _name of directive that this auto directive will render to.

        "_name" is used instead of "name because:
        self.directive.name is a property object - not a meaningful value because
        directive is a directive TYPE, not an instance.
        Directive.name can not become a classproperty because that would disable the
        ability to override directive names.
        """
        return self.directive._name

    @property
    @cache
    def watch_dirs(self):
        app_static_dirs = []
        app_paths = {conf.name: conf.path for conf in apps.app_configs.values()}
        for app in self._watch_apps:
            expected_static = Path(app_paths[app]) / "static"
            if expected_static.is_dir():
                app_static_dirs.append(expected_static)
        absolute_watch_dirs = [dir.absolute() for dir in self._watch_dirs]

        return list(set(absolute_watch_dirs + app_static_dirs))

    def on_any_event(self, event: FileSystemEvent):
        """
        Handle all FileSystemEvents from Watchdog. For newly created, modified or moved
        files, call compute_value. Remove directive static_values for deleted files.
        """
        resource = Path(event.src_path)

        if resource.is_dir() or resource.suffix != self.suffix:
            return

        if isinstance(event, FileMovedEvent):
            # Remove hash of old file
            self.files.pop(resource.absolute(), None)
            # Then we just treat it like creation / modification of the "destination"
            resource = Path(event.dest_path)

        if isinstance(event, (FileModifiedEvent, FileCreatedEvent, FileMovedEvent)):
            self.files[resource.absolute()] = self.compute_value_item(resource)
        if isinstance(event, FileDeletedEvent):
            self.files.pop(resource.absolute(), None)

    def init_files(self):
        """
        Make sure all local files have a value in self.files.
        """
        initial_paths: Set[Path] = {
            file
            for watch_dir in self.watch_dirs
            for file in watch_dir.rglob(f"*{self.suffix}")
        }
        for p in initial_paths:
            if p not in self.files:
                self.files[p] = self.compute_value_item(p)

    @init_before_first_render
    def render(self, **kwargs) -> DirectiveType:
        # Sorting to avoid non-deterministic tests
        items = sorted(self.files.items())
        # Default implementation assumes that compute_value_item returns ValueItemType
        values = cast(Tuple[ValueItemType, ...], tuple(v for p, v in items))
        return self.directive(*self.static_values, *values)


class AutoHostSrc(AutoSrcDirective[DirectiveType, str], metaclass=ABCMeta):
    """
    Computes "source-expressions" for a -src CSP. For local files the URL is
    constructed. For external sources their src-attribute is used. Host and scheme for
    local files are added when rendered.
    """

    def __init__(
        self,
        *static_values: SourceExpression,
        scheme: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        **kwargs,
    ):
        super().__init__(*static_values, **kwargs)
        self.scheme = scheme
        self.host = host
        self.port = port

    def compute_value_item(self, path: Path) -> str:
        """
        Create relative url for -src directive, the complete URL is computed in render.
        """
        for stat_dir in self.watch_dirs:
            if path.is_relative_to(stat_dir):
                return static(str(path.relative_to(stat_dir)))

        raise ValueError(
            f"Could not find {path} in any watch dir. Probably a watchdog observer is"
            " misconfigured."
        )

    @init_before_first_render
    @fill_render_args("scheme", "host", optional=["port"])
    def render(
        self,
        *,
        scheme: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        **kwargs,
    ) -> DirectiveType:
        if scheme is None or host is None:
            maybe_missing = {"scheme": scheme, "host": host}
            missing = [k for k, v in maybe_missing.items() if v is None]
            raise ValuesMissing(
                f"Attempted to render urls for {self.name}, but some "
                f"required value(s) where neither found on the directives attributes "
                f"nor in the render arguments: {', '.join(missing)}",
                names=missing,
            )

        origin = f"{scheme}://{host}"

        if port is not None:
            origin = f"{origin}:{port}"

        # Sorting to avoid non-deterministic tests

        # TODO: sort by path instead of value
        paths = sorted(self.files.values())
        dynamic = [HostSrc(f"{origin}{path}") for path in paths]

        return self.directive(*self.static_values, *dynamic)


# TODO: Revisit
#  I only discovered after implementing AutoHashSrc that Firefox only supports cksums
#  for inline elements and NOT for anything loaded via URLs. The use-case for this
#  AutoDirective would thus be limited to chrome and break firefox without adding
#  more source expressions ('self' or HostSrces) to allow the tracked files.
#  That would in turn defeat any security benefit gained from using cksums.
#  Different CSPs for different browsers is something I do not want to advocate since
#  it contradicts the core idea of this project:
#  Nail your CSP down in one place and deploy it as statically as possible!


# from content_security_policy.django.utils import get_file_hash
# from content_security_policy.values import HashSrc
# class AutoHashSrc(AutoSrcDirective[DirectiveType, HashSrc], metaclass=ABCMeta):
#     """
#     Computes "source-hashes" for a -src CSP. Local files are hashed whenever they
#     change.
#     """
#
#     def compute_value_item(self, path: Path) -> HashSrc:
#         """
#         Compute hash of file and create value for -src directive.
#         """
#
#         return HashSrc(
#             f"'{SRC_HASH_FUN}-" f"{get_file_hash(path, hash_name=SRC_HASH_FUN)}'"
#         )
