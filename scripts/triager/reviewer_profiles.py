"""
Reviewer profiles for CPython PR triage.

Built directly from the actual python/cpython .github/CODEOWNERS file.
No API calls needed — this is static knowledge derived from the file
you can always find at:
  https://github.com/python/cpython/blob/main/.github/CODEOWNERS

Each reviewer profile contains:
  - subsystems: what areas they own
  - co_owners: who else owns the same areas (cross-review partners)
  - focus_keywords: technical terms they care about in review
  - known_concerns: what they typically ask about (from studying their PRs)
  - devguide_url: their entry in the CPython experts index

These are used to:
  1. Enrich CODEOWNERS routing with human context
  2. Seed the reviewer_activity module with targeted search terms
  3. Give the AI synthesis layer per-reviewer context
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReviewerProfile:
    """Static profile for one CPython reviewer."""

    username: str
    display_name: str
    subsystems: list[str]
    co_owners: list[str]

    # Technical keywords this reviewer focuses on.
    # Used to weight review comment searches.
    focus_keywords: list[str] = field(default_factory=list)

    # Known concerns extracted from studying their real review comments.
    # These are what they actually say, not generic advice.
    known_concerns: list[str] = field(default_factory=list)

    # Approximate response time signal (days). None = unknown.
    typical_response_days: float | None = None

    devguide_url: str = ""

    @property
    def github_url(self) -> str:
        return f"https://github.com/{self.username}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "display_name": self.display_name,
            "subsystems": self.subsystems,
            "co_owners": self.co_owners,
            "focus_keywords": self.focus_keywords,
            "known_concerns": self.known_concerns,
            "typical_response_days": self.typical_response_days,
            "github_url": self.github_url,
            "devguide_url": self.devguide_url,
        }


# ---------------------------------------------------------------------------
# Canonical reviewer profiles
# Derived from CODEOWNERS + studying real CPython PR review history
# ---------------------------------------------------------------------------

PROFILES: dict[str, ReviewerProfile] = {

    "markshannon": ReviewerProfile(
        username="markshannon",
        display_name="Mark Shannon",
        subsystems=[
            "bytecodes", "ceval", "compiler", "dict", "frame",
            "type objects", "optimizer", "call", "code objects",
            "genobject", "cases_generator",
        ],
        co_owners=["iritkatriel", "Fidget-Spinner", "tomasr8", "savannahostrowski"],
        focus_keywords=[
            "performance", "benchmark", "specializing", "adaptive",
            "tier-2", "micro-op", "uop", "bytecode", "stack",
            "eval loop", "regen-cases", "generated_cases",
        ],
        known_concerns=[
            "Is this the minimal change to bytecodes.c?",
            "Have you regenerated Python/generated_cases.c.h? (make regen-cases)",
            "Does this affect the specializing adaptive interpreter?",
            "Please add a benchmark showing this doesn't regress performance",
            "This adds a branch to the hot path — is it justified?",
            "The stack effect is wrong",
            "This needs to handle the error path correctly",
        ],
        typical_response_days=3.0,
        devguide_url="https://devguide.python.org/core-developers/experts/#bytecode",
    ),

    "iritkatriel": ReviewerProfile(
        username="iritkatriel",
        display_name="Irit Katriel",
        subsystems=[
            "compiler", "assembler", "codegen", "flowgraph",
            "exceptions", "instruction_sequence",
        ],
        co_owners=["markshannon", "eclips4"],
        focus_keywords=[
            "compiler", "flowgraph", "assembler", "basic block",
            "exception table", "lineno", "co_linetable",
        ],
        known_concerns=[
            "The exception table entry is incorrect",
            "This changes the compiler output — please check the dis output",
            "The line number information needs updating",
            "Does this handle the case where the exception is raised inside a loop?",
        ],
        typical_response_days=4.0,
    ),

    "picnixz": ReviewerProfile(
        username="picnixz",
        display_name="Bénédikt Tran",
        subsystems=[
            "ssl", "hashlib", "hmac", "blake", "md5", "sha",
            "pyhash", "cryptographic primitives", "hashopenssl",
        ],
        co_owners=["gpshead"],
        focus_keywords=[
            "ssl", "tls", "openssl", "hashlib", "hmac", "digest",
            "constant time", "side channel", "cryptographic", "EVP",
            "certificate", "cipher", "entropy",
        ],
        known_concerns=[
            "Is this comparison constant-time? Side-channel risk?",
            "Does this use the EVP API correctly?",
            "OpenSSL version compatibility — what's the minimum we support?",
            "This needs a test with an expired/invalid certificate",
            "The error message leaks information about the internal state",
            "Use hashlib.new() instead of the direct constructor",
        ],
        typical_response_days=5.0,
    ),

    "ZeroIntensity": ReviewerProfile(
        username="ZeroIntensity",
        display_name="Peter Bierma",
        subsystems=[
            "C API docs", "object.c", "pylifecycle", "pystate",
            "c-api",
        ],
        co_owners=["ericsnowcurrently", "FFY00"],
        focus_keywords=[
            "C API", "stable ABI", "limited API", "Py_INCREF",
            "Py_DECREF", "reference count", "lifetime", "ownership",
            "lifecycle", "Py_tp_", "PyType_Slot",
        ],
        known_concerns=[
            "This changes the public C API — we need a deprecation path",
            "Reference ownership: who owns this reference after this call?",
            "Is Py_XDECREF needed here instead of Py_DECREF?",
            "This is not available in the Limited API",
            "The documentation for this C function is missing/incorrect",
            "Does this handle tp_traverse correctly for GC?",
        ],
        typical_response_days=4.0,
    ),

    "encukou": ReviewerProfile(
        username="encukou",
        display_name="Petr Viktorin",
        subsystems=[
            "stable ABI", "limited C API", "tomllib",
            "Argument Clinic", "ABI check",
        ],
        co_owners=["erlend-aasland", "hauntsaninja"],
        focus_keywords=[
            "stable ABI", "limited API", "Py_LIMITED_API",
            "Py_TPFLAGS_", "PyType_Spec", "clinic", "clinic input",
            "stable_abi.toml", "libabigail",
        ],
        known_concerns=[
            "This function must be added to Misc/stable_abi.toml",
            "Is this available in the Limited C API?",
            "Please convert to Argument Clinic",
            "The ABI check (libabigail) will catch this",
            "run: python Tools/build/stable_abi.py --generate",
            "This changes a struct layout — ABI break on stable branches",
        ],
        typical_response_days=5.0,
    ),

    "gpshead": ReviewerProfile(
        username="gpshead",
        display_name="Gregory P. Smith",
        subsystems=[
            "ssl", "hashlib", "hmac", "multiprocessing",
            "subprocess", "socket", "pyhash",
        ],
        co_owners=["picnixz"],
        focus_keywords=[
            "security", "subprocess", "shell injection", "socket",
            "ssl", "tls", "multiprocessing", "fork", "spawn",
            "signal", "race condition", "file descriptor",
        ],
        known_concerns=[
            "shell=True is dangerous here — can we avoid it?",
            "This is a potential race condition (TOCTOU)",
            "File descriptor leak on error path",
            "Does this work correctly after fork()?",
            "The socket timeout handling is incorrect",
            "This needs a security note in the documentation",
        ],
        typical_response_days=7.0,
    ),

    "pablogsal": ReviewerProfile(
        username="pablogsal",
        display_name="Pablo Galindo Salgado",
        subsystems=[
            "grammar", "parser", "PEG", "GC", "PyREPL",
            "remote debugging", "profiling", "tokenize",
        ],
        co_owners=["lysnikolaou", "ambv"],
        focus_keywords=[
            "grammar", "PEG", "pegen", "tokenize", "parser",
            "garbage collector", "GC", "cyclic", "finalize",
            "PyREPL", "readline", "remote debug", "profiling",
            "regen-pegen", "regen-all",
        ],
        known_concerns=[
            "Run: make regen-pegen && make regen-all after Grammar/ changes",
            "Does this grammar change maintain backward compatibility?",
            "The GC traversal function (tp_traverse) needs updating",
            "This breaks in the presence of cycles with __del__",
            "Please add a test to Lib/test/test_peg_generator/",
            "The tokenizer state machine needs to handle this case",
        ],
        typical_response_days=4.0,
    ),

    "lysnikolaou": ReviewerProfile(
        username="lysnikolaou",
        display_name="Lysandros Nikolaou",
        subsystems=[
            "grammar", "tokenize", "PyREPL", "t-strings",
            "template literals", "parser",
        ],
        co_owners=["pablogsal", "ambv"],
        focus_keywords=[
            "tokenize", "grammar", "t-string", "template",
            "interpolation", "PyREPL", "readline",
        ],
        known_concerns=[
            "The tokenizer needs to handle this at the lexer level",
            "t-strings interact with this — please add a test",
            "This changes the grammar — run regen-pegen",
        ],
        typical_response_days=4.0,
    ),

    "JelleZijlstra": ReviewerProfile(
        username="JelleZijlstra",
        display_name="Jelle Zijlstra",
        subsystems=[
            "typing", "annotations", "AST", "typevar",
            "union types", "annotationlib", "symtable",
        ],
        co_owners=["AlexWaygood", "isidentical", "eclips4", "tomasr8", "carljm"],
        focus_keywords=[
            "typing", "annotations", "PEP 563", "PEP 649",
            "TypeVar", "ParamSpec", "TypeVarTuple", "Union",
            "overload", "Protocol", "runtime", "evaluate",
            "get_type_hints", "annotationlib",
        ],
        known_concerns=[
            "Does this work with PEP 649 (deferred annotations)?",
            "get_type_hints() needs to handle this case",
            "TypeVar bounds/constraints need testing",
            "Please add a test in Lib/test/test_typing.py",
            "This changes runtime behavior of annotations",
            "Does this affect typing.get_annotations()?",
            "Protocol compatibility needs verification",
        ],
        typical_response_days=3.0,
    ),

    "AlexWaygood": ReviewerProfile(
        username="AlexWaygood",
        display_name="Alex Waygood",
        subsystems=["typing", "annotations"],
        co_owners=["JelleZijlstra"],
        focus_keywords=["typing", "type checker", "mypy", "pyright"],
        known_concerns=[
            "Does mypy/pyright handle this correctly?",
            "Please add a typing test",
        ],
        typical_response_days=3.0,
    ),

    "ericsnowcurrently": ReviewerProfile(
        username="ericsnowcurrently",
        display_name="Eric Snow",
        subsystems=[
            "import system", "GIL", "subinterpreters", "runtime state",
            "lifecycle", "pystate", "pylifecycle", "builtins", "sys",
            "freeze", "frozen", "modsupport", "moduleobject",
        ],
        co_owners=["brettcannon", "ncoghlan", "warsaw", "FFY00", "ZeroIntensity"],
        focus_keywords=[
            "subinterpreter", "per-interpreter", "GIL", "free-threading",
            "runtime state", "_PyRuntime", "tstate", "interp",
            "import lock", "module spec", "multi-phase init",
            "cross-interpreter",
        ],
        known_concerns=[
            "Is this state per-interpreter or global?",
            "This uses global state — needs to be per-interpreter for PEP 684",
            "Import lock: is this holding it when it shouldn't?",
            "Multi-phase initialization: exec_module vs create_module",
            "Does this work correctly in subinterpreters?",
            "The module state struct needs updating",
            "This bypasses the import system — why?",
        ],
        typical_response_days=7.0,
    ),

    "brettcannon": ReviewerProfile(
        username="brettcannon",
        display_name="Brett Cannon",
        subsystems=["import system", "importlib", "devguide", "WASI"],
        co_owners=["ericsnowcurrently", "ncoghlan", "warsaw", "FFY00"],
        focus_keywords=[
            "import", "loader", "finder", "spec", "importlib",
            "sys.path", "sys.modules", "__import__",
        ],
        known_concerns=[
            "Does this follow the import system protocol?",
            "The finder/loader distinction matters here",
            "This needs to work with frozen modules",
            "Please check the importlib documentation",
        ],
        typical_response_days=7.0,
    ),

    "1st1": ReviewerProfile(
        username="1st1",
        display_name="Yury Selivanov",
        subsystems=["asyncio", "contextvars", "HAMT"],
        co_owners=["asvetlov", "kumaraditya303", "willingc"],
        focus_keywords=[
            "asyncio", "event loop", "coroutine", "Task", "Future",
            "CancelledError", "Shield", "gather", "TaskGroup",
            "contextvars", "Context", "HAMT", "await",
        ],
        known_concerns=[
            "Task cancellation must be handled correctly here",
            "Does this work when the event loop is already running?",
            "Context variables need to be propagated in Tasks",
            "CancelledError should not be swallowed",
            "This changes the scheduling order — is that intentional?",
            "TaskGroup exception propagation needs testing",
        ],
        typical_response_days=10.0,
    ),

    "asvetlov": ReviewerProfile(
        username="asvetlov",
        display_name="Andrew Svetlov",
        subsystems=["asyncio"],
        co_owners=["1st1", "kumaraditya303", "willingc"],
        focus_keywords=[
            "asyncio", "event loop", "transport", "protocol",
            "StreamReader", "StreamWriter", "selector",
        ],
        known_concerns=[
            "Transport/Protocol contract must be preserved",
            "Does this handle connection_lost() correctly?",
            "The event loop policy is deprecated — use the loop parameter",
        ],
        typical_response_days=7.0,
    ),

    "kumaraditya303": ReviewerProfile(
        username="kumaraditya303",
        display_name="Kumar Aditya",
        subsystems=["asyncio", "weakref", "import"],
        co_owners=["1st1", "asvetlov"],
        focus_keywords=["asyncio", "weakref", "import", "free-threading"],
        known_concerns=[
            "Weakref callbacks can fire at unexpected times",
            "Does this work under free-threading?",
        ],
        typical_response_days=3.0,
    ),

    "rhettinger": ReviewerProfile(
        username="rhettinger",
        display_name="Raymond Hettinger",
        subsystems=[
            "collections", "functools", "itertools", "random",
            "heapq", "bisect", "set", "OrderedDict",
        ],
        co_owners=[],
        focus_keywords=[
            "recipe", "algorithm", "performance", "O(n)", "complexity",
            "pure Python", "C implementation", "collections.abc",
            "MutableMapping", "iterator protocol",
        ],
        known_concerns=[
            "This changes the documented recipe — is that intentional?",
            "The pure Python and C versions must stay in sync",
            "Time complexity: what's the big-O of this operation?",
            "Does this preserve the iterator protocol?",
            "The collections.abc registration needs updating",
            "This should be a recipe in the docs, not a new function",
        ],
        typical_response_days=5.0,
    ),

    "vsajip": ReviewerProfile(
        username="vsajip",
        display_name="Vinay Sajip",
        subsystems=["logging", "venv"],
        co_owners=[],
        focus_keywords=[
            "logging", "handler", "formatter", "filter", "logger",
            "LogRecord", "basicConfig", "fileConfig", "dictConfig",
        ],
        known_concerns=[
            "This changes logging behavior that users depend on",
            "Thread safety: logging handlers must be thread-safe",
            "Does this affect dictConfig() compatibility?",
            "The logging cookbook example needs updating",
            "Backward compat: this format change will break existing code",
        ],
        typical_response_days=7.0,
    ),

    "barneygale": ReviewerProfile(
        username="barneygale",
        display_name="Barney Gale",
        subsystems=["pathlib"],
        co_owners=[],
        focus_keywords=[
            "pathlib", "Path", "PurePath", "PosixPath", "WindowsPath",
            "flavour", "glob", "walk", "stat", "symlink",
        ],
        known_concerns=[
            "Does this work on both POSIX and Windows?",
            "Symlink handling: is the follow_symlinks behavior correct?",
            "glob() patterns have edge cases on Windows",
            "The pathlib flavour distinction matters here",
            "Does this preserve the Path subclassing contract?",
        ],
        typical_response_days=3.0,
    ),

    "ericvsmith": ReviewerProfile(
        username="ericvsmith",
        display_name="Eric V. Smith",
        subsystems=["dataclasses"],
        co_owners=[],
        focus_keywords=[
            "dataclass", "field", "__post_init__", "InitVar",
            "ClassVar", "frozen", "slots", "__dataclass_fields__",
        ],
        known_concerns=[
            "Does this work with frozen=True?",
            "ClassVar fields must not be included in __init__",
            "InitVar fields need special handling in __post_init__",
            "Does this interact correctly with inheritance?",
            "field(default_factory=) behavior needs testing",
            "Slots dataclasses have different semantics here",
        ],
        typical_response_days=5.0,
    ),

    "erlend-aasland": ReviewerProfile(
        username="erlend-aasland",
        display_name="Erlend Egeberg Aasland",
        subsystems=["SQLite", "Argument Clinic", "build system", "dbm"],
        co_owners=["AA-Turner"],
        focus_keywords=[
            "sqlite3", "SQLite", "clinic", "Argument Clinic",
            "clinic input", "make clinic", "autoconf", "configure",
            "Makefile", "dbm",
        ],
        known_concerns=[
            "Please convert to Argument Clinic: run Tools/clinic/clinic.py",
            "The Argument Clinic output needs regenerating",
            "SQLite version compatibility — what's the minimum?",
            "Does this handle the sqlite3 error codes correctly?",
            "The docstring in the clinic block needs updating",
        ],
        typical_response_days=4.0,
    ),

    "AA-Turner": ReviewerProfile(
        username="AA-Turner",
        display_name="Adam Turner",
        subsystems=[
            "documentation", "build", "calendar", "types",
            "pydoc", "zstd", "CI", "InternalDocs",
        ],
        co_owners=["hugovk", "StanFromIreland"],
        focus_keywords=[
            "documentation", "Sphinx", "rst", "docstring",
            "versionadded", "versionchanged", "deprecated",
            "Doc/conf.py", "build", "nitpick",
        ],
        known_concerns=[
            ".. versionadded:: 3.XX is missing",
            ".. versionchanged:: 3.XX is missing",
            "The docstring needs a .. deprecated:: directive",
            "Sphinx nitpick: this reference is broken",
            "The What's New entry should mention this",
            "This needs a .. note:: about the behavior difference",
        ],
        typical_response_days=3.0,
    ),

    "hugovk": ReviewerProfile(
        username="hugovk",
        display_name="Hugo van Kemenade",
        subsystems=["documentation", "CI", "colorize", "GitHub config"],
        co_owners=["AA-Turner", "StanFromIreland"],
        focus_keywords=[
            "CI", "GitHub Actions", "documentation", "typo",
            "rst", "colorize", "pre-commit",
        ],
        known_concerns=[
            "Typo in documentation",
            "The CI workflow needs updating",
            "pre-commit hook should catch this",
        ],
        typical_response_days=2.0,
    ),

    "StanFromIreland": ReviewerProfile(
        username="StanFromIreland",
        display_name="Stan Ulbrych",
        subsystems=["zlib", "datetime", "turtle", "documentation"],
        co_owners=["AA-Turner", "pganssle"],
        focus_keywords=["zlib", "datetime", "docs", "turtle"],
        known_concerns=[
            "zlib version compatibility needs checking",
            "datetime arithmetic edge case",
        ],
        typical_response_days=4.0,
    ),

    "pganssle": ReviewerProfile(
        username="pganssle",
        display_name="Paul Ganssle",
        subsystems=["datetime", "time", "zoneinfo"],
        co_owners=["StanFromIreland"],
        focus_keywords=[
            "datetime", "date", "time", "timezone", "tzinfo",
            "zoneinfo", "UTC", "DST", "fold", "ambiguous",
            "IANA", "tzdata",
        ],
        known_concerns=[
            "DST fold handling: is the fold attribute set correctly?",
            "Does this handle ambiguous times (DST transitions) correctly?",
            "UTC vs local time: is the conversion correct?",
            "The tzinfo interface contract must be preserved",
            "Does this work without tzdata installed?",
            "Leap second handling",
        ],
        typical_response_days=7.0,
    ),

    "gaogaotiantian": ReviewerProfile(
        username="gaogaotiantian",
        display_name="Tian Gao",
        subsystems=["pdb", "bdb"],
        co_owners=[],
        focus_keywords=[
            "pdb", "bdb", "debugger", "breakpoint", "trace",
            "settrace", "frame", "lineno", "remote pdb",
        ],
        known_concerns=[
            "Does this work with remote pdb?",
            "The trace function must handle all events",
            "Breakpoint condition evaluation needs error handling",
            "Does this interact correctly with sys.settrace?",
        ],
        typical_response_days=4.0,
    ),

    "ethanfurman": ReviewerProfile(
        username="ethanfurman",
        display_name="Ethan Furman",
        subsystems=["enum", "tarfile"],
        co_owners=[],
        focus_keywords=[
            "Enum", "IntEnum", "Flag", "IntFlag", "StrEnum",
            "auto()", "member", "non-member", "_missing_",
            "tarfile", "tar", "archive",
        ],
        known_concerns=[
            "Does this work with Flag members?",
            "_missing_() hook behavior needs testing",
            "Enum member vs non-member distinction",
            "Does this preserve the enum string representation?",
            "tarfile security: path traversal check",
        ],
        typical_response_days=7.0,
    ),

    "sethmlarson": ReviewerProfile(
        username="sethmlarson",
        display_name="Seth Michael Larson",
        subsystems=["SBOM", "supply chain security"],
        co_owners=[],
        focus_keywords=[
            "SBOM", "SPDX", "supply chain", "dependency",
            "vulnerability", "CVE", "security advisory",
        ],
        known_concerns=[
            "The SBOM needs updating for this dependency change",
            "This introduces a new vendored dependency — update SBOM",
        ],
        typical_response_days=5.0,
    ),

    "FFY00": ReviewerProfile(
        username="FFY00",
        display_name="Filipe Laíns",
        subsystems=[
            "build", "getpath", "sysconfig", "importlib",
            "WASI", "site",
        ],
        co_owners=["emmatyping", "brettcannon", "AA-Turner"],
        focus_keywords=[
            "sysconfig", "build", "platform", "WASI",
            "cross-compile", "getpath", "sys.path",
        ],
        known_concerns=[
            "Cross-compilation compatibility",
            "WASI has no filesystem access by default",
            "sysconfig variables differ per platform",
        ],
        typical_response_days=5.0,
    ),

    "brandtbucher": ReviewerProfile(
        username="brandtbucher",
        display_name="Brandt Bucher",
        subsystems=["JIT", "pattern matching"],
        co_owners=["savannahostrowski", "diegorusso"],
        focus_keywords=[
            "JIT", "stencil", "copy-and-patch", "LLVM",
            "pattern matching", "match", "case", "guard",
        ],
        known_concerns=[
            "JIT stencil generation needs regenerating",
            "Does this work on all JIT-supported platforms?",
            "Pattern matching: structural vs value patterns",
        ],
        typical_response_days=5.0,
    ),

    "Fidget-Spinner": ReviewerProfile(
        username="Fidget-Spinner",
        display_name="Ken Jin",
        subsystems=["Tier-2 optimizer", "stackref"],
        co_owners=["markshannon", "tomasr8"],
        focus_keywords=[
            "optimizer", "uop", "micro-op", "tier-2",
            "stackref", "deopt", "guard", "trace",
        ],
        known_concerns=[
            "The optimizer analysis needs updating",
            "Guard failure path must be correct",
            "stackref semantics: borrowed vs owned",
        ],
        typical_response_days=5.0,
    ),

    "jaraco": ReviewerProfile(
        username="jaraco",
        display_name="Jason R. Coombs",
        subsystems=["importlib.metadata", "importlib.resources", "configparser", "zipfile"],
        co_owners=["warsaw", "FFY00"],
        focus_keywords=[
            "importlib.metadata", "importlib.resources",
            "configparser", "zipfile", "entry_points",
            "distribution", "package metadata",
        ],
        known_concerns=[
            "Entry point group naming conventions",
            "Does this work with namespace packages?",
            "importlib.resources: traversable interface",
        ],
        typical_response_days=7.0,
    ),

    "giampaolo": ReviewerProfile(
        username="giampaolo",
        display_name="Giampaolo Rodolà",
        subsystems=["shutil", "ftplib"],
        co_owners=[],
        focus_keywords=["shutil", "copy", "disk_usage", "ftplib", "FTP"],
        known_concerns=[
            "Does this preserve file permissions on copy?",
            "Symlink handling in shutil",
            "FTP passive mode handling",
        ],
        typical_response_days=7.0,
    ),

    "serhiy-storchaka": ReviewerProfile(
        username="serhiy-storchaka",
        display_name="Serhiy Storchaka",
        subsystems=["many stdlib modules", "dbm", "codecs"],
        co_owners=[],
        focus_keywords=[
            "performance", "memory", "codec", "unicode",
            "struct", "pickle", "optimization",
        ],
        known_concerns=[
            "This can be simplified",
            "Memory allocation: check for overflow",
            "Unicode handling edge case",
            "The C implementation needs updating too",
        ],
        typical_response_days=5.0,
    ),

    "ezio-melotti": ReviewerProfile(
        username="ezio-melotti",
        display_name="Ezio Melotti",
        subsystems=["html", "GitHub config"],
        co_owners=[],
        focus_keywords=["html", "parser", "entities", "encoding"],
        known_concerns=["HTML5 entity handling", "encoding edge case"],
        typical_response_days=10.0,
    ),

    "mhsmith": ReviewerProfile(
        username="mhsmith",
        display_name="Malcolm Smith",
        subsystems=["Android"],
        co_owners=["freakboy3742"],
        focus_keywords=["Android", "JNI", "Java", "APK", "Gradle"],
        known_concerns=[
            "Does this work on all supported Android API levels?",
            "JNI reference management",
        ],
        typical_response_days=7.0,
    ),

    "freakboy3742": ReviewerProfile(
        username="freakboy3742",
        display_name="Russell Keith-Magee",
        subsystems=["iOS", "Android", "Emscripten"],
        co_owners=["mhsmith", "emmatyping"],
        focus_keywords=["iOS", "Android", "Emscripten", "mobile", "cross-platform"],
        known_concerns=[
            "Mobile platforms have restricted APIs",
            "Does this work without fork()?",
            "Emscripten has no threads by default",
        ],
        typical_response_days=7.0,
    ),

    "terryjreedy": ReviewerProfile(
        username="terryjreedy",
        display_name="Terry Jan Reedy",
        subsystems=["IDLE", "turtle"],
        co_owners=[],
        focus_keywords=["IDLE", "tkinter", "turtle", "editor", "shell"],
        known_concerns=[
            "IDLE has its own test suite: Lib/idlelib/idle_test/",
            "tkinter version compatibility",
            "Does this work on macOS Aqua?",
        ],
        typical_response_days=5.0,
    ),

    "gvanrossum": ReviewerProfile(
        username="gvanrossum",
        display_name="Guido van Rossum",
        subsystems=["typing", "language design"],
        co_owners=["JelleZijlstra", "AlexWaygood"],
        focus_keywords=[
            "typing", "PEP", "language design", "syntax",
            "type checker", "runtime behavior",
        ],
        known_concerns=[
            "This needs a PEP before implementation",
            "Does this break any existing type checkers?",
            "The runtime behavior must match the type system semantics",
            "This is a language change — needs broader discussion",
        ],
        typical_response_days=14.0,
    ),

    "vstinner": ReviewerProfile(
        username="vstinner",
        display_name="Victor Stinner",
        subsystems=[
            "performance", "C API", "Unicode", "memory",
            "free-threading",
        ],
        co_owners=[],
        focus_keywords=[
            "performance", "benchmark", "pyperf", "C API",
            "unicode", "UTF-8", "memory", "free-threading",
            "thread safety", "atomic",
        ],
        known_concerns=[
            "Please run pyperf to check for performance regression",
            "This C API change needs a deprecation in 3.XX",
            "Unicode fast-path may be bypassed here",
            "Thread safety: is this operation atomic?",
            "Memory: check for integer overflow in size calculation",
        ],
        typical_response_days=5.0,
    ),
}


def get_profile(username: str) -> ReviewerProfile | None:
    """Look up a reviewer profile by GitHub username."""
    clean = username.lstrip("@")
    return PROFILES.get(clean)


def enrich_experts(
    experts: list[dict],
) -> list[dict]:
    """
    Add reviewer profile context to a list of CODEOWNERS matches.

    Each expert dict gets a 'profile' key with the reviewer's known
    concerns, focus keywords, co-owners, and typical response time.
    Returns the enriched list — experts without profiles are included
    unchanged.
    """
    result = []
    for expert in experts:
        enriched = dict(expert)
        username = str(expert.get("owner", "")).lstrip("@")
        profile = PROFILES.get(username)
        if profile:
            enriched["profile"] = profile.as_dict()
        result.append(enriched)
    return result


def subsystem_reviewers(subsystem: str) -> list[ReviewerProfile]:
    """
    Find reviewers who own a given subsystem keyword.

    Case-insensitive partial match against profile.subsystems.
    """
    key = subsystem.lower()
    return [
        profile
        for profile in PROFILES.values()
        if any(key in s.lower() for s in profile.subsystems)
    ]


def co_reviewer_suggestions(
    experts: list[dict],
    max_suggestions: int = 3,
) -> list[str]:
    """
    Suggest additional reviewers based on co-ownership patterns.

    Given a list of CODEOWNERS matches, return usernames of co-owners
    who are not already in the list but share ownership of the same areas.
    """
    already = {
        str(e.get("owner", "")).lstrip("@")
        for e in experts
    }
    suggestions: list[str] = []
    seen: set[str] = set(already)

    for expert in experts:
        username = str(expert.get("owner", "")).lstrip("@")
        profile = PROFILES.get(username)
        if not profile:
            continue
        for co in profile.co_owners:
            if co not in seen:
                seen.add(co)
                suggestions.append(co)
            if len(suggestions) >= max_suggestions:
                return suggestions

    return suggestions