"""Stage 1 Zero-Trust Secure Runner (`kintsugi.runtime.secure_runner`).

Re-verifies every trust, attestation, on-disk integrity, permission,
path-confinement, and PreToolUse guardrail invariant at execution time before
running an explicitly allowlisted local Python callable or `shell=False`
subprocess inside the confined workspace.
"""

from __future__ import annotations

import abc
import base64
import builtins
import collections
import ctypes
import dataclasses
import datetime
import dis
import enum
import fcntl
import fractions
import functools
import gc
import hashlib
import hmac
import inspect
import io
import ipaddress
import json
import logging
import math
import mmap
import opcode
import os
import platform
import posixpath
import re
import resource
import secrets
import selectors
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import uuid
from decimal import Decimal
from enum import Enum
from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from typing import Any, Callable, Dict, FrozenSet, Iterator, List, Mapping, Optional, Sequence, Set, Tuple, Union

from kintsugi.capability.contracts_v2 import extract_exact_adapter_spec_dict
from kintsugi.capability.schemas import (
    ExecutionReceipt,
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    TrustStatus,
    assert_execution_receipt_type_unmodified,
    compute_tool_spec_security_digest,
    extract_exact_security_context_dict,
    extract_exact_tool_spec_dict,
    has_valid_verification_attestation,
    is_valid_sha256,
    normalize_sha256,
    redact_secrets_in_text,
    redact_secrets_in_value,
    safe_exact_str_dict_view,
    sanitize_exact_json_value,
    sha256_digest,
    validate_safe_text,
)
_VALID_SECURITY_PROFILES: FrozenSet[str] = frozenset(p.value for p in SecurityProfile)
from kintsugi.capability.tool_registry import AttestationAuthority
from kintsugi.config import KintsugiConfig
from kintsugi.forge.tool_sandbox import (
    ToolSandbox,
    build_seatbelt_profile,
    run_subprocess_streaming_bounded,
)
from kintsugi.hooks import evaluate_claude_pre_tool_payload
from kintsugi.ledger import ScarLedger
from kintsugi.process_tree import EXEC_TOKEN_NAME, new_execution_token, terminate_execution_tree
from kintsugi.models import GoldenScar
from kintsugi.shield import (
    OUTBOUND_DLP_SECRET_RE,
    PROMPT_INJECTION_RE,
    TROJAN_UNICODE_RE,
    assert_not_symlink,
    redact_high_entropy_secrets,
    resolve_safe_child_path,
)

DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_OUTPUT_BYTES = 262144

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TOOL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_ENV_KEYS: Tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "LC_CTYPE")
_NETWORK_PERMISSIONS: FrozenSet[str] = frozenset(
    {"network", "network.outbound", "network.inbound", "net", "http", "https", "socket", "web"}
)
_NETWORK_VERBS: FrozenSet[str] = frozenset(
    {"curl", "wget", "nc", "ncat", "ssh", "scp", "sftp", "rsync", "ftp", "telnet", "socat"}
)
_NATIVE_PERMISSIONS: FrozenSet[str] = frozenset(
    {"native", "native.exec", "native.untrusted", "untrusted_native"}
)
_PATH_ARG_KEY_HINTS: FrozenSet[str] = frozenset({
    "path", "file", "dir", "root", "target", "src", "dst", "dest", "input",
    "output", "cwd", "script", "filename", "filepath", "files", "paths", "targets", "workspace",
})
_SENSITIVE_PATH_FRAGMENTS: Tuple[str, ...] = (
    "/.ssh", ".ssh/", "id_rsa", "id_ed25519", "/.aws", ".aws/", "/.gnupg", "/etc/passwd", "/etc/shadow",
)
_PEM_REDACT_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE " + r"KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE " + r"KEY-----"
)
_BEARER_REDACT_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._-]{16,}")
_USER_PATH_REDACT_RE = re.compile(r"(?:/Users/|/home/|C:\\\\Users\\\\|C:\\Users\\)[A-Za-z0-9._-]+")
_HOME_ENV_VAR_RE = re.compile(r"\$(?:\{?\s*(?:HOME|USER|LOGNAME|PWD|SSH_AUTH_SOCK)\s*\}?)")
_SECRET_KEY_NAME_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|credential|auth)"
)


def canonical_sha256(obj: Any) -> str:
    """Compute canonical `sha256:<hex>` digest delegating to `schemas.sha256_digest`."""
    return sha256_digest(obj)


def normalize_sha256_hex(digest: str) -> str:
    """Normalize an optional `sha256:` prefix to lowercase 64-char hex, or empty string."""
    raw = str(digest or "").strip().lower()
    if raw.startswith("sha256:"):
        raw = raw.split(":", 1)[1].strip()
    return raw if _SHA256_HEX_RE.fullmatch(raw) else ""


def trust_status_value(val: Any) -> str:
    """Extract normalized uppercase trust status string from an Enum or string."""
    raw = val.value if hasattr(val, "value") else val
    return str(raw or "").strip().upper()


def redact_runtime_text(text: Any, max_len: int = 0) -> str:
    """Redact credentials, high-entropy literals, Bidi chars, and local user paths."""
    cleaned = str(text or "")
    if not cleaned:
        return ""
    cleaned = TROJAN_UNICODE_RE.sub("", cleaned)
    cleaned = _PEM_REDACT_RE.sub("[REDACTED_PRIVATE_KEY]", cleaned)
    cleaned = _BEARER_REDACT_RE.sub(r"\1[REDACTED_TOKEN]", cleaned)
    cleaned = redact_secrets_in_text(cleaned, redact_paths=False)
    cleaned = redact_high_entropy_secrets(cleaned)
    cleaned = _USER_PATH_REDACT_RE.sub("/Users/<redacted>", cleaned)
    cleaned = OUTBOUND_DLP_SECRET_RE.sub("[REDACTED_SECRET]", cleaned)
    return cleaned[:max_len] if (max_len > 0 and len(cleaned) > max_len) else cleaned


def redact_runtime_value(value: Any, *, key_hint: str = "") -> Any:
    """Recursively redact sensitive strings inside nested JSON-compatible structures."""
    redacted_base = redact_secrets_in_value(value, key_hint=key_hint)
    if isinstance(redacted_base, str):
        if key_hint and _SECRET_KEY_NAME_RE.search(key_hint) and not redacted_base.startswith("[REDACTED"):
            return "[REDACTED_SECRET]"
        return redact_runtime_text(redacted_base)
    if isinstance(redacted_base, (list, tuple)):
        return [redact_runtime_value(v, key_hint=key_hint) for v in redacted_base]
    if isinstance(redacted_base, dict):
        return {
            redact_runtime_text(str(k)): redact_runtime_value(v, key_hint=str(k))
            for k, v in redacted_base.items()
        }
    return redacted_base


_STDLIB_TYPE_MODULE_PREFIXES: Tuple[str, ...] = (
    "builtins",
    "collections",
    "ctypes",
    "datetime",
    "decimal",
    "enum",
    "functools",
    "hashlib",
    "hmac",
    "io",
    "json",
    "logging",
    "math",
    "os",
    "pathlib",
    "posixpath",
    "re",
    "resource",
    "shutil",
    "signal",
    "socket",
    "stat",
    "struct",
    "subprocess",
    "sys",
    "tempfile",
    "threading",
    "time",
    "types",
    "typing",
    "unittest",
)
_CLASSMETHOD_DESCRIPTOR_TYPE = getattr(types, "ClassMethodDescriptorType", type(dict.fromkeys))
_STDLIB_BUILTIN_TYPES = (
    types.BuiltinFunctionType,
    types.BuiltinMethodType,
    types.MethodDescriptorType,
    types.WrapperDescriptorType,
    types.GetSetDescriptorType,
    types.MemberDescriptorType,
    _CLASSMETHOD_DESCRIPTOR_TYPE,
)
_FFI_FORBIDDEN_TYPES: Tuple[type, ...] = tuple(
    t
    for t in (
        getattr(ctypes, "_CFuncPtr", None),
        getattr(ctypes, "CDLL", None),
        getattr(ctypes, "LibraryLoader", None),
    )
    if isinstance(t, type)
)
_SKIP_RUNTIME_HANDLE_NAMES: FrozenSet[str] = frozenset(
    {"SecureRunner", "ToolRegistry", "AttestationAuthority", "ExperienceStore"}
)
_FORBIDDEN_CALLABLE_NAMES: FrozenSet[str] = frozenset({
    "globals",
    "locals",
    "vars",
    "getattr",
    "setattr",
    "delattr",
    "eval",
    "exec",
    "compile",
    "__import__",
    "importlib",
    "_getframe",
    "currentframe",
    "__globals__",
    "__builtins__",
    "__dict__",
    "__subclasses__",
    "__mro__",
    "__bases__",
    "__code__",
    "__closure__",
    "__getattribute__",
    "__loader__",
    "__spec__",
})
_EMPTY_CELL_MARKER = object()
_MISSING_GLOBAL_MARKER = object()
_UNSET_SLOT_MARKER = object()
_MAX_CANONICAL_DEPTH = 64
_MAX_CANONICAL_BUDGET = 16384
_AUDIT_EXEC_PERMISSIONS: FrozenSet[str] = frozenset({"process.exec", "compile_c", "run_asan", "shell.exec"})
_ALLOWED_METACLASSES: FrozenSet[Any] = frozenset({
    type,
    abc.ABCMeta,
    enum.EnumMeta,
    getattr(enum, "EnumType", enum.EnumMeta),
})
_ALLOWED_DESCRIPTOR_TYPES: Tuple[type, ...] = (
    types.FunctionType,
    staticmethod,
    classmethod,
    property,
    types.GetSetDescriptorType,
    types.MemberDescriptorType,
    types.MethodDescriptorType,
    types.WrapperDescriptorType,
    types.BuiltinFunctionType,
    types.BuiltinMethodType,
    _CLASSMETHOD_DESCRIPTOR_TYPE,
)
_ENUM_PROPERTY_TYPE = getattr(enum, "property", types.DynamicClassAttribute)
_SAFE_STDLIB_DESCRIPTOR_TYPES: Tuple[type, ...] = tuple(
    dict.fromkeys([
        functools.cached_property,
        types.DynamicClassAttribute,
        _ENUM_PROPERTY_TYPE,
    ])
)
_ALLOWED_MAPPING_PROXY_BACKING_TYPES: FrozenSet[type] = frozenset(
    {dict}
    | {
        type(r)
        for r in gc.get_referents(type.__dict__["__dict__"].__get__(ctypes.c_int))
        if r is not types.MappingProxyType and type.__getattribute__(type(r), "__base__") is dict
    }
)
_SAFE_STDLIB_REPR_TYPES: FrozenSet[type] = frozenset({
    complex,
    range,
    datetime.date,
    datetime.datetime,
    datetime.time,
    datetime.timedelta,
    datetime.timezone,
    uuid.UUID,
    fractions.Fraction,
    ipaddress.IPv4Address,
    ipaddress.IPv6Address,
    ipaddress.IPv4Network,
    ipaddress.IPv6Network,
    ipaddress.IPv4Interface,
    ipaddress.IPv6Interface,
})
_RESERVED_ENUM_STORAGE_ATTRS: FrozenSet[str] = frozenset({"_name_", "_value_", "__objclass__"})
_ALLOWED_STDLIB_CLASS_HELPER_ATTRS: FrozenSet[str] = frozenset({
    "__replace__",
    "__getstate__",
    "__setstate__",
    "__repr__",
    "__str__",
    "__format__",
    "__new__",
    "_generate_next_value_",
    "__reduce_ex__",
    "__copy__",
    "__deepcopy__",
    "__dir__",
    "_missing_",
    "_new_member_",
})
_TRUSTED_STDLIB_HELPER_SYMBOL_NAMES: FrozenSet[str] = frozenset({
    "_replace",
    "_dataclass_getstate",
    "_dataclass_setstate",
    "_generate_next_value_",
    "__repr__",
    "__str__",
    "__format__",
    "__new__",
    "__reduce_ex__",
    "__copy__",
    "__deepcopy__",
    "__dir__",
    "_missing_",
    "_new_member_",
})


def _collect_trusted_stdlib_class_helpers() -> FrozenSet[types.FunctionType]:
    helpers: Set[types.FunctionType] = set()
    dc_dict = object.__getattribute__(dataclasses, "__dict__")
    for name in ("_replace", "replace", "_dataclass_getstate", "_dataclass_setstate"):
        fn = dc_dict.get(name) if type(dc_dict) is dict else None
        if type(fn) is types.FunctionType:
            helpers.add(fn)
    enum_bases = [enum.Enum, enum.IntEnum, enum.Flag, enum.IntFlag]
    strenum_cls = getattr(enum, "StrEnum", None)
    if type(strenum_cls) is not None and isinstance(strenum_cls, type):
        enum_bases.append(strenum_cls)
    for e_cls in enum_bases:
        e_dict = type.__getattribute__(e_cls, "__dict__")
        for key in _TRUSTED_STDLIB_HELPER_SYMBOL_NAMES:
            if key not in e_dict:
                continue
            val = e_dict[key]
            if type(val) in (staticmethod, classmethod):
                val = val.__func__
            if type(val) is types.FunctionType:
                helpers.add(val)
    return frozenset(helpers)


_TRUSTED_STDLIB_CLASS_HELPERS: FrozenSet[types.FunctionType] = _collect_trusted_stdlib_class_helpers()
_SKIP_TYPE_METADATA_ATTRS: FrozenSet[str] = frozenset({
    "__module__",
    "__doc__",
    "__dict__",
    "__weakref__",
    "__annotations__",
    "__firstlineno__",
    "__static_attributes__",
    "__orig_bases__",
    "__parameters__",
})
_PREFLIGHT_FORBIDDEN_ATTR_HOOKS: FrozenSet[str] = frozenset({
    "__getattribute__",
    "__getattr__",
})
_EXACT_PRIMITIVE_TYPES: Tuple[type, ...] = (
    bool,
    int,
    float,
    str,
    bytes,
    bytearray,
    Decimal,
    PurePath,
    PurePosixPath,
    PureWindowsPath,
    Path,
    PosixPath,
    WindowsPath,
    re.Pattern,
)
_TYPE_DICT_DESCR = type.__dict__["__dict__"]
_TYPE_MRO_DESCR = type.__dict__["__mro__"]
_TYPE_MODULE_DESCR = type.__dict__["__module__"]
_TYPE_QUALNAME_DESCR = type.__dict__["__qualname__"]
_TYPE_NAME_DESCR = type.__dict__["__name__"]
_IMPORT_NAME_OP: int = int(dis.opmap.get("IMPORT_NAME", -1))
_EXTENDED_ARG_OP: int = int(dis.opmap.get("EXTENDED_ARG", 144))
_HAVE_ARGUMENT: int = int(getattr(dis, "HAVE_ARGUMENT", 90))
_BYTECODE_INT_OVERFLOW: int = 1 << 31
_OS_ENVIRON_OBJ = os.environ


def _build_inline_cache_table(raw_cache: Any, opmap_obj: Any) -> Tuple[int, ...]:
    """Build a 256-entry immutable inline-cache count tuple for Python 3.9–3.13+."""
    cache_list = [0] * 256
    opmap_clean = dict(opmap_obj) if isinstance(opmap_obj, Mapping) else {}
    if type(raw_cache) is dict:
        for k, v in raw_cache.items():
            if type(v) is not int or v < 0:
                continue
            if type(k) is int and 0 <= k < 256:
                cache_list[k] = v
            elif type(k) is str:
                code_idx = opmap_clean.get(k)
                if type(code_idx) is int and 0 <= code_idx < 256:
                    cache_list[code_idx] = v
    elif isinstance(raw_cache, (list, tuple)):
        for idx in range(min(256, len(raw_cache))):
            v = raw_cache[idx]
            if type(v) is int and v >= 0:
                cache_list[idx] = v
    return tuple(cache_list)


def _build_bytecode_tables() -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
    """Snapshot immutable deopt & inline-cache tables at import time (immune to runtime `dis` patches)."""
    deopt_fn = getattr(dis, "_deoptop", None)
    if not callable(deopt_fn):
        deopt_fn = getattr(opcode, "_deoptop", None)
    deopt_list: List[int] = []
    for op in range(256):
        mapped = op
        if callable(deopt_fn):
            try:
                cand = deopt_fn(op)
                if type(cand) is int and 0 <= cand < 256:
                    mapped = cand
            except (KeyError, IndexError, TypeError, ValueError):
                mapped = op
        deopt_list.append(mapped)

    raw_cache = getattr(dis, "_inline_cache_entries", None)
    if raw_cache is None:
        raw_cache = getattr(opcode, "_inline_cache_entries", None)
    cache_tuple = _build_inline_cache_table(raw_cache, getattr(dis, "opmap", {}))
    return tuple(deopt_list), cache_tuple


_DEOP_MAP, _INLINE_CACHE_ENTRIES = _build_bytecode_tables()


_STDLIB_ROOT_PREFIXES: Tuple[str, ...] = tuple(
    dict.fromkeys([
        sys.prefix,
        sys.base_prefix,
        os.path.realpath(sys.prefix),
        os.path.realpath(sys.base_prefix),
    ])
)
_EXTRA_STDLIB_TOP_MODULES: FrozenSet[str] = frozenset({
    "abc",
    "codecs",
    "copyreg",
    "ctypes",
    "_ctypes",
    "dataclasses",
    "encodings",
    "enum",
    "fcntl",
    "genericpath",
    "linecache",
    "mmap",
    "ntpath",
    "posix",
    "posixpath",
    "selectors",
    "traceback",
    "warnings",
    "_collections_abc",
    "_sitebuiltins",
})


def _is_stdlib_file_path(mod_file: Any) -> bool:
    if type(mod_file) is not str or not mod_file or "site-packages" in mod_file:
        return False
    return any(mod_file.startswith(pfx + os.sep) for pfx in _STDLIB_ROOT_PREFIXES)


def _safe_type_dict(cls: type) -> Mapping[str, Any]:
    return _TYPE_DICT_DESCR.__get__(cls, type)


def _safe_type_mro(cls: type) -> Tuple[type, ...]:
    return _TYPE_MRO_DESCR.__get__(cls, type)


def _is_type_in(t: type, candidates: Union[Tuple[type, ...], FrozenSet[type]]) -> bool:
    """Check class membership strictly by C pointer identity (`is`), never calling metaclass `__eq__`/`__hash__`."""
    for item in candidates:
        if t is item:
            return True
    return False


def _has_base_in_mro(cls: type, targets: Union[type, Tuple[type, ...]]) -> bool:
    target_tuple = targets if type(targets) is tuple else (targets,)
    for base in _safe_type_mro(cls):
        for target in target_tuple:
            if base is target:
                return True
    return False


def _safe_fn_module(fn: types.FunctionType) -> str:
    raw = object.__getattribute__(fn, "__module__")
    return raw if type(raw) is str else ""


def _safe_fn_qualname(fn: types.FunctionType) -> str:
    for attr in ("__qualname__", "__name__"):
        raw = object.__getattribute__(fn, attr)
        if type(raw) is str and raw:
            return raw
    return ""


def _safe_mappingproxy_dict(mp: types.MappingProxyType) -> Optional[Dict[Any, Any]]:
    """Return the underlying C `dict` (or authentic `_ctypes.StgDict`) of a `MappingProxyType` without calling Python methods."""
    refs = [r for r in gc.get_referents(mp) if r is not types.MappingProxyType]
    if len(refs) == 1 and _is_type_in(type(refs[0]), _ALLOWED_MAPPING_PROXY_BACKING_TYPES):
        return refs[0]
    return None


def _safe_str_dict_view(mapping: Any) -> Optional[Dict[str, Any]]:
    """Copy a C dict or mappingproxy linearly, failing closed (`None`) if any key is not an exact `str`."""
    mt = type(mapping)
    if mt is dict:
        pairs = list(dict.items(mapping))
    elif mt is types.MappingProxyType:
        raw_backing = _safe_mappingproxy_dict(mapping)
        if raw_backing is None:
            return None
        pairs = list(dict.items(raw_backing))
    else:
        return None
    clean: Dict[str, Any] = {}
    for k, v in pairs:
        if type(k) is not str:
            return None
        clean[k] = v
    return clean


def _safe_namespace_str_keys(ns: Any) -> Optional[List[str]]:
    clean = _safe_str_dict_view(ns)
    if clean is None:
        return None
    return sorted(clean.keys())


def _safe_sys_module_exact(name: str) -> Any:
    """Lookup `name` in `sys.modules` without invoking `__hash__`/`__eq__` on non-str keys."""
    if type(name) is not str or not name:
        return None
    if all(type(k) is str for k in dict.keys(sys.modules)):
        return dict.get(sys.modules, name)
    for k, v in dict.items(sys.modules):
        if type(k) is str and k == name:
            return v
    return None


def _safe_sys_module_get(name: str) -> Any:
    """Lookup `name` then top-level package in `sys.modules` using identity `is None` (zero `__bool__`)."""
    if type(name) is not str or not name:
        return None
    mod_obj = _safe_sys_module_exact(name)
    if mod_obj is not None or "." not in name:
        return mod_obj
    top = name.split(".", 1)[0]
    return _safe_sys_module_exact(top)


def _is_allowed_metaclass(mc: type) -> bool:
    if _is_type_in(mc, _ALLOWED_METACLASSES):
        return True
    if not _is_type_in(type(mc), _ALLOWED_METACLASSES):
        return False
    mc_td = _safe_str_dict_view(_safe_type_dict(mc))
    if mc_td is None:
        return False
    mc_mod = mc_td.get("__module__")
    if type(mc_mod) is not str:
        raw_mod = _TYPE_MODULE_DESCR.__get__(mc, type)
        mc_mod = raw_mod if type(raw_mod) is str else ""
    if not _is_stdlib_module_name(mc_mod):
        return False
    for hk in _PREFLIGHT_FORBIDDEN_ATTR_HOOKS:
        hfn = mc_td.get(hk)
        if type(hfn) is types.FunctionType and not _is_stdlib_module_name(_safe_fn_module(hfn)):
            return False
    return True


def _safe_type_module(cls: type) -> str:
    td = _safe_str_dict_view(_safe_type_dict(cls))
    if td is None:
        return ""
    raw_mod = td.get("__module__")
    if type(raw_mod) is str:
        return raw_mod
    if _is_allowed_metaclass(type(cls)):
        fallback_mod = _TYPE_MODULE_DESCR.__get__(cls, type)
        if type(fallback_mod) is str:
            return fallback_mod
    return ""


def _safe_type_qualname(cls: type) -> str:
    td = _safe_str_dict_view(_safe_type_dict(cls))
    if td is None:
        return ""
    for k in ("__qualname__", "__name__"):
        if k in td and type(td[k]) is str:
            return td[k]
    if _is_allowed_metaclass(type(cls)):
        qn = _TYPE_QUALNAME_DESCR.__get__(cls, type)
        if type(qn) is str and qn:
            return qn
        nm = _TYPE_NAME_DESCR.__get__(cls, type)
        if type(nm) is str:
            return nm
    return ""


def _is_stdlib_module_name(mod_name: str) -> bool:
    """Return True if `mod_name` belongs to Python stdlib or builtin namespace."""
    name = mod_name if type(mod_name) is str else ""
    if not name:
        return False
    if name in sys.builtin_module_names:
        return True
    top = name.split(".", 1)[0]
    if top == "kintsugi":
        return False
    if top in sys.builtin_module_names or top in _EXTRA_STDLIB_TOP_MODULES:
        return True
    stdlib_names = getattr(sys, "stdlib_module_names", None)
    if stdlib_names is not None and top in stdlib_names:
        return True
    if any(name == p or name.startswith(p + ".") for p in _STDLIB_TYPE_MODULE_PREFIXES):
        return True
    mod_obj = _safe_sys_module_get(name)
    if type(mod_obj) is types.ModuleType:
        mod_view = _safe_str_dict_view(object.__getattribute__(mod_obj, "__dict__"))
        mod_file = mod_view.get("__file__") if mod_view is not None else None
        if _is_stdlib_file_path(mod_file):
            return True
    return False


def _is_stdlib_module(mod: types.ModuleType) -> bool:
    """Return True only when `mod` is an authentic stdlib module in `sys.modules`."""
    if type(mod) is not types.ModuleType:
        return False
    mod_view = _safe_str_dict_view(object.__getattribute__(mod, "__dict__"))
    if mod_view is None:
        return False
    mod_name = mod_view.get("__name__", "")
    if type(mod_name) is not str or not mod_name or _safe_sys_module_exact(mod_name) is not mod:
        return False
    if _is_stdlib_module_name(mod_name):
        return True
    if _is_stdlib_file_path(mod_view.get("__file__")):
        return True
    return False


def _is_authentic_stdlib_class_helper(attr_name: str, fn: types.FunctionType) -> bool:
    """Return True only for authentic stdlib-generated class helpers such as Python 3.13 `dataclasses._replace`."""
    if attr_name not in _ALLOWED_STDLIB_CLASS_HELPER_ATTRS:
        return False
    if any(fn is helper for helper in _TRUSTED_STDLIB_CLASS_HELPERS):
        return True
    fn_mod = _safe_fn_module(fn)
    if fn_mod not in {"dataclasses", "enum", "reprlib"}:
        return False
    mod_obj = _safe_sys_module_exact(fn_mod)
    if mod_obj is None or not _is_stdlib_module(mod_obj):
        return False
    mod_dict = object.__getattribute__(mod_obj, "__dict__")
    mod_view = _safe_str_dict_view(mod_dict)
    if mod_view is None:
        return False
    fn_globals = object.__getattribute__(fn, "__globals__")
    if fn_globals is not mod_dict:
        return False
    code_obj = object.__getattribute__(fn, "__code__")
    if type(code_obj) is not types.CodeType:
        return False
    mod_file = mod_view.get("__file__")
    if type(mod_file) is not str or not _is_stdlib_file_path(mod_file) or code_obj.co_filename != mod_file:
        return False
    if _collect_code_names(code_obj) & _FORBIDDEN_CALLABLE_NAMES or _collect_code_import_names(code_obj):
        return False
    return True


def _validate_class_preflight_safety(cls: type) -> Optional[str]:
    """Verify via pure C-level `type.__getattribute__` that inspecting `cls` cannot execute user hooks."""
    mc = type(cls)
    if not _is_allowed_metaclass(mc):
        return "CALLABLE_CUSTOM_METACLASS_FORBIDDEN"
    if mc is not type:
        mc_dict = _safe_str_dict_view(_safe_type_dict(mc))
        if mc_dict is None:
            return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
        for hk in _PREFLIGHT_FORBIDDEN_ATTR_HOOKS:
            hfn = mc_dict.get(hk)
            if type(hfn) is types.FunctionType and not _is_stdlib_module_name(_safe_fn_module(hfn)):
                return "CALLABLE_CUSTOM_METACLASS_FORBIDDEN"
    is_enum_cls = _has_base_in_mro(cls, Enum)
    for base in _safe_type_mro(cls):
        if base is object:
            continue
        base_dict = _safe_str_dict_view(_safe_type_dict(base))
        if base_dict is None:
            return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
        base_mod = _safe_type_module(base)
        if _is_stdlib_module_name(base_mod):
            for hk in _PREFLIGHT_FORBIDDEN_ATTR_HOOKS:
                hfn = base_dict.get(hk)
                if type(hfn) is types.FunctionType and not _is_stdlib_module_name(_safe_fn_module(hfn)):
                    return f"CALLABLE_CUSTOM_ATTRIBUTE_HOOK_FORBIDDEN:{hk}"
        else:
            for hk in _PREFLIGHT_FORBIDDEN_ATTR_HOOKS:
                if hk in base_dict:
                    return f"CALLABLE_CUSTOM_ATTRIBUTE_HOOK_FORBIDDEN:{hk}"
            if "__dict__" in base_dict and type(base_dict["__dict__"]) is not types.GetSetDescriptorType:
                return "CALLABLE_CUSTOM_ATTRIBUTE_HOOK_FORBIDDEN:__dict__"
            if is_enum_cls:
                for rk in _RESERVED_ENUM_STORAGE_ATTRS:
                    if rk in base_dict and type(base_dict[rk]) is not types.MemberDescriptorType:
                        return f"CALLABLE_CUSTOM_ATTRIBUTE_HOOK_FORBIDDEN:{rk}"
        for attr_name, attr_val in base_dict.items():
            av_cls = type(attr_val)
            if _is_type_in(av_cls, _ALLOWED_DESCRIPTOR_TYPES) or _is_type_in(av_cls, _SAFE_STDLIB_DESCRIPTOR_TYPES):
                continue
            if not _is_allowed_metaclass(type(av_cls)):
                return f"CALLABLE_CUSTOM_DESCRIPTOR_FORBIDDEN:{attr_name}"
            for d_base in _safe_type_mro(av_cls):
                if d_base is object:
                    continue
                d_dict = _safe_str_dict_view(_safe_type_dict(d_base))
                if d_dict is None:
                    return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                if "__get__" in d_dict or "__set__" in d_dict or "__delete__" in d_dict:
                    return f"CALLABLE_CUSTOM_DESCRIPTOR_FORBIDDEN:{attr_name}"
    return None


def _safe_instance_dict(obj: Any, cls: type) -> Optional[dict]:
    """Read an instance's `__dict__` directly via C `GetSetDescriptorType` without `__getattribute__`."""
    for base in _safe_type_mro(cls):
        if base is object:
            continue
        bd = _safe_str_dict_view(_safe_type_dict(base))
        if bd is None:
            continue
        desc = bd.get("__dict__")
        if type(desc) is types.GetSetDescriptorType:
            raw = desc.__get__(obj, cls)
            if type(raw) is dict:
                return raw
    return None


def _safe_instance_slots(obj: Any, cls: type) -> List[Tuple[str, Any]]:
    """Read populated `__slots__` directly via C `MemberDescriptorType` without `getattr`."""
    slot_map: Dict[str, Any] = {}
    for base in _safe_type_mro(cls):
        if base is object or _is_stdlib_module_name(_safe_type_module(base)):
            continue
        bd = _safe_str_dict_view(_safe_type_dict(base))
        if bd is None:
            continue
        slots_raw = bd.get("__slots__")
        if slots_raw is None:
            continue
        if type(slots_raw) is str:
            slot_names: Tuple[str, ...] = (slots_raw,)
        elif type(slots_raw) is tuple or type(slots_raw) is list:
            slot_names = tuple(s for s in slots_raw if type(s) is str)
        else:
            continue
        base_name = _safe_type_qualname(base).rsplit(".", 1)[-1].lstrip("_")
        for sname in slot_names:
            if sname in {"__dict__", "__weakref__"}:
                continue
            lookup_name = (
                f"_{base_name}{sname}"
                if sname.startswith("__") and not sname.endswith("__") and base_name
                else sname
            )
            if lookup_name in slot_map or lookup_name not in bd:
                continue
            desc = bd[lookup_name]
            if type(desc) is types.MemberDescriptorType:
                try:
                    sval = desc.__get__(obj, cls)
                except AttributeError:
                    sval = _UNSET_SLOT_MARKER
                if sval is not _UNSET_SLOT_MARKER:
                    slot_map[lookup_name] = sval
    return sorted(slot_map.items(), key=lambda kv: kv[0])


def _safe_enum_name_value(obj: Any, cls: type) -> Tuple[Optional[str], Any, Optional[str]]:
    """Read Enum `_name_` and `_value_` strictly from C storage without triggering keys/descriptors."""
    raw_dict = _safe_instance_dict(obj, cls)
    slots = _safe_instance_slots(obj, cls)
    raw_name: Any = _UNSET_SLOT_MARKER
    raw_val: Any = _UNSET_SLOT_MARKER
    if type(raw_dict) is dict:
        clean_dict = _safe_str_dict_view(raw_dict)
        if clean_dict is None:
            return (None, None, "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN")
        if "_name_" in clean_dict:
            raw_name = clean_dict["_name_"]
        if "_value_" in clean_dict:
            raw_val = clean_dict["_value_"]
    for sname, sval in slots:
        if raw_name is _UNSET_SLOT_MARKER and sname == "_name_":
            raw_name = sval
        elif raw_val is _UNSET_SLOT_MARKER and sname == "_value_":
            raw_val = sval
    if raw_name is _UNSET_SLOT_MARKER or raw_val is _UNSET_SLOT_MARKER or type(raw_name) is not str or not raw_name:
        return (None, None, "CALLABLE_CUSTOM_ATTRIBUTE_HOOK_FORBIDDEN:_name_")
    return (raw_name, raw_val, None)


def _safe_builtin_subclass_payload(obj: Any) -> Optional[Tuple[str, Any]]:
    """Extract raw C storage from subclasses of builtin containers/scalars without user overrides."""
    obj_t = type(obj)
    if obj_t is not dict and _has_base_in_mro(obj_t, dict):
        return ("dict", list(dict.items(obj)))
    if obj_t is not list and _has_base_in_mro(obj_t, list):
        return ("list", list(list.__iter__(obj)))
    if obj_t is not tuple and _has_base_in_mro(obj_t, tuple):
        return ("tuple", list(tuple.__iter__(obj)))
    if obj_t is not frozenset and _has_base_in_mro(obj_t, frozenset):
        return ("frozenset", list(frozenset.__iter__(obj)))
    if obj_t is not set and _has_base_in_mro(obj_t, set):
        return ("set", list(set.__iter__(obj)))
    if obj_t is not int and not _has_base_in_mro(obj_t, bool) and _has_base_in_mro(obj_t, int):
        return ("int", int.__repr__(obj))
    if obj_t is not float and _has_base_in_mro(obj_t, float):
        return ("float", float.__repr__(obj))
    if obj_t is not str and not _has_base_in_mro(obj_t, Enum) and _has_base_in_mro(obj_t, str):
        return ("str", str.__str__(obj))
    if obj_t is not bytes and _has_base_in_mro(obj_t, bytes):
        return ("bytes", bytes.__getitem__(obj, slice(None)))
    if obj_t is not bytearray and _has_base_in_mro(obj_t, bytearray):
        return ("bytearray", bytes(bytearray.__getitem__(obj, slice(None))))
    return None


def _is_skippable_runtime_obj(obj: Any) -> bool:
    """Return True for non-serializable logger/lock/IO/env/harness manager runtime objects."""
    if obj is _OS_ENVIRON_OBJ:
        return True
    cls = type(obj)
    if _validate_class_preflight_safety(cls) is not None:
        return False
    mod_name = _safe_type_module(cls)
    cls_name = _safe_type_qualname(cls).rsplit(".", 1)[-1]
    if _is_stdlib_module_name(mod_name):
        if _has_base_in_mro(cls, (logging.Logger, io.IOBase, selectors.BaseSelector, socket.socket)):
            return True
        if mod_name == "_thread":
            return True
    if cls_name in _SKIP_RUNTIME_HANDLE_NAMES and mod_name.startswith("kintsugi."):
        return True
    return False


def _collect_code_names(code_obj: types.CodeType, visited: Optional[Set[int]] = None) -> Set[str]:
    seen = visited if visited is not None else set()
    cid = id(code_obj)
    if cid in seen:
        return set()
    seen.add(cid)
    names: Set[str] = {n for n in (code_obj.co_names or ()) if type(n) is str}
    for const in (code_obj.co_consts or ()):
        if type(const) is types.CodeType:
            names.update(_collect_code_names(const, seen))
    return names


def _collect_code_string_consts(code_obj: types.CodeType, visited: Optional[Set[int]] = None) -> Set[str]:
    seen = visited if visited is not None else set()
    cid = id(code_obj)
    if cid in seen:
        return set()
    seen.add(cid)
    strings: Set[str] = set()
    for const in (code_obj.co_consts or ()):
        if type(const) is str and const:
            strings.add(const)
        elif type(const) is types.CodeType:
            strings.update(_collect_code_string_consts(const, seen))
    return strings


def _iter_bytecode_opargs(raw_code: bytes) -> Iterator[Tuple[int, int, Optional[int]]]:
    """Yield `(offset, deopt_op, arg)` cross-version for Python 3.9–3.13+ without touching `dis`."""
    extended_arg = 0
    caches = 0
    n = len(raw_code)
    i = 0
    while i + 1 < n:
        if caches:
            caches -= 1
            i += 2
            continue
        op = raw_code[i]
        deop = _DEOP_MAP[op]
        caches = _INLINE_CACHE_ENTRIES[deop]
        if deop >= _HAVE_ARGUMENT or deop == _EXTENDED_ARG_OP:
            arg = raw_code[i + 1] | extended_arg
            if deop == _EXTENDED_ARG_OP:
                extended_arg = arg << 8
                if extended_arg >= _BYTECODE_INT_OVERFLOW:
                    extended_arg -= 2 * _BYTECODE_INT_OVERFLOW
            else:
                extended_arg = 0
        else:
            arg = None
            extended_arg = 0
        yield (i, deop, arg)
        i += 2


def _collect_code_import_names(code_obj: types.CodeType, visited: Optional[Set[int]] = None) -> Set[str]:
    """Collect static `IMPORT_NAME` module names via immutable bytecode tables (zero `repr()`, zero `dis` hook)."""
    seen = visited if visited is not None else set()
    cid = id(code_obj)
    if cid in seen:
        return set()
    seen.add(cid)
    imports: Set[str] = set()
    raw_code = code_obj.co_code
    raw_names = code_obj.co_names
    if _IMPORT_NAME_OP >= 0 and type(raw_code) is bytes and type(raw_names) is tuple:
        for _off, op, arg in _iter_bytecode_opargs(raw_code):
            if op == _IMPORT_NAME_OP and type(arg) is int and 0 <= arg < len(raw_names):
                nm = raw_names[arg]
                if type(nm) is str and nm:
                    imports.add(nm)
    for const in (code_obj.co_consts or ()):
        if type(const) is types.CodeType:
            imports.update(_collect_code_import_names(const, seen))
    return imports


def _check_memoryview_backing_error(mv: memoryview) -> Optional[str]:
    """Return hygiene error code if live `memoryview` wraps forbidden `mmap` or FFI object."""
    try:
        mv_obj = mv.obj
    except ValueError:
        return None
    mv_obj_t = type(mv_obj)
    if mv_obj_t is mmap.mmap or _has_base_in_mro(mv_obj_t, mmap.mmap):
        return "CALLABLE_SHARED_MMAP_FORBIDDEN"
    if _FFI_FORBIDDEN_TYPES and _has_base_in_mro(mv_obj_t, _FFI_FORBIDDEN_TYPES):
        return "CALLABLE_NATIVE_FFI_OBJECT_FORBIDDEN"
    return None


def _lookup_fn_builtin(fn_globals: Any, name: str) -> Any:
    """Resolve builtin `name` from per-function `fn.__globals__['__builtins__']` via zero-hook str-keyed views."""
    fg_view = _safe_str_dict_view(fn_globals) if type(fn_globals) is dict else None
    fn_builtins = fg_view.get("__builtins__", builtins) if fg_view is not None else builtins
    if type(fn_builtins) is dict:
        bview = _safe_str_dict_view(fn_builtins)
        if bview is not None and name in bview:
            return bview[name]
    elif type(fn_builtins) is types.ModuleType:
        bview = _safe_str_dict_view(object.__getattribute__(fn_builtins, "__dict__"))
        if bview is not None and name in bview:
            return bview[name]
    return getattr(builtins, name, _MISSING_GLOBAL_MARKER)


def validate_trusted_host_callable_hygiene(fn: Callable[..., Any]) -> Optional[str]:
    """Reject dynamic namespace/introspection primitives, FFI handles, shared mmaps, unsafe hooks, or depth overflow."""
    visited: Set[int] = set()
    budget = [_MAX_CANONICAL_BUDGET]

    def _scan_stdlib_helper_fn(
        target_fn: types.FunctionType,
        depth: int,
        *,
        caller_names: Optional[FrozenSet[str]] = None,
    ) -> Optional[str]:
        if depth > _MAX_CANONICAL_DEPTH or budget[0] <= 0:
            return "CALLABLE_HYGIENE_DEPTH_OR_BUDGET_EXCEEDED"
        budget[0] -= 1
        h_oid = id(target_fn)
        if h_oid in visited:
            return None
        visited.add(h_oid)
        for def_v in (object.__getattribute__(target_fn, "__defaults__") or ()):
            err = _scan_value(def_v, depth + 1, check_callables=True, caller_names=caller_names)
            if err:
                return err
        kw_d = object.__getattribute__(target_fn, "__kwdefaults__")
        if type(kw_d) is dict:
            if _safe_namespace_str_keys(kw_d) is None:
                return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
            for kw_v in dict.values(kw_d):
                err = _scan_value(kw_v, depth + 1, check_callables=True, caller_names=caller_names)
                if err:
                    return err
        for cell in (object.__getattribute__(target_fn, "__closure__") or ()):
            try:
                cval = cell.cell_contents
            except ValueError as _cell_err:
                _ = _cell_err
                continue
            err = _scan_value(cval, depth + 1, check_callables=True, caller_names=caller_names)
            if err:
                return err
        return None

    def _scan_value(
        val: Any,
        depth: int,
        *,
        check_callables: bool,
        caller_names: Optional[FrozenSet[str]] = None,
    ) -> Optional[str]:
        if depth > _MAX_CANONICAL_DEPTH or budget[0] <= 0:
            return "CALLABLE_HYGIENE_DEPTH_OR_BUDGET_EXCEEDED"
        budget[0] -= 1

        val_t = type(val)
        if val is None or val is Ellipsis or val is NotImplemented or val_t is object or _is_type_in(val_t, _EXACT_PRIMITIVE_TYPES):
            return None
        if val_t is slice:
            for part in (val.start, val.stop, val.step):
                err = _scan_value(part, depth + 1, check_callables=False, caller_names=caller_names)
                if err:
                    return err
            return None
        if val_t is mmap.mmap or _has_base_in_mro(val_t, mmap.mmap):
            return "CALLABLE_SHARED_MMAP_FORBIDDEN"
        if val_t is memoryview:
            mv_err = _check_memoryview_backing_error(val)
            if mv_err:
                return mv_err
            try:
                mv_obj = val.obj
            except ValueError:
                return None
            return _scan_value(mv_obj, depth + 1, check_callables=False, caller_names=caller_names)
        if _FFI_FORBIDDEN_TYPES and _has_base_in_mro(val_t, _FFI_FORBIDDEN_TYPES):
            return "CALLABLE_NATIVE_FFI_OBJECT_FORBIDDEN"
        if _is_type_in(val_t, _STDLIB_BUILTIN_TYPES):
            bound_self = getattr(val, "__self__", None)
            if bound_self is not None and type(bound_self) is not types.ModuleType:
                return _scan_value(bound_self, depth + 1, check_callables=False, caller_names=caller_names)
            return None
        if _is_skippable_runtime_obj(val):
            return None
        if val_t is types.ModuleType or _has_base_in_mro(val_t, types.ModuleType):
            if val_t is not types.ModuleType:
                safety_err = _validate_class_preflight_safety(val_t)
                if safety_err:
                    return safety_err
            oid = id(val)
            if oid in visited:
                return None
            visited.add(oid)
            mod_dict = object.__getattribute__(val, "__dict__") if val_t is types.ModuleType else _safe_instance_dict(val, val_t)
            if _is_stdlib_module(val):
                if type(mod_dict) is dict:
                    mod_view = _safe_str_dict_view(mod_dict)
                    if mod_view is None:
                        return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                    keys = [k for k in sorted(mod_view.keys()) if k in caller_names] if caller_names else []
                    for v_any in mod_view.values():
                        v_any_t = type(v_any)
                        if v_any_t is mmap.mmap or _has_base_in_mro(v_any_t, mmap.mmap):
                            return "CALLABLE_SHARED_MMAP_FORBIDDEN"
                        if v_any_t is memoryview:
                            mv_err = _check_memoryview_backing_error(v_any)
                            if mv_err:
                                return mv_err
                        if _FFI_FORBIDDEN_TYPES and _has_base_in_mro(v_any_t, _FFI_FORBIDDEN_TYPES):
                            return "CALLABLE_NATIVE_FFI_OBJECT_FORBIDDEN"
                    for k in keys:
                        err = _scan_value(
                            mod_view[k],
                            depth + 1,
                            check_callables=False,
                            caller_names=caller_names,
                        )
                        if err:
                            return err
                return None
            if type(mod_dict) is dict:
                mod_view = _safe_str_dict_view(mod_dict)
                if mod_view is None:
                    return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                for k in sorted(mod_view.keys()):
                    if k.startswith("__"):
                        continue
                    err = _scan_value(mod_view[k], depth + 1, check_callables=False)
                    if err:
                        return err
            return None
        oid = id(val)
        if oid in visited:
            return None
        visited.add(oid)

        if _has_base_in_mro(val_t, Enum):
            safety_err = _validate_class_preflight_safety(val_t)
            if safety_err:
                return safety_err
            _ename, enum_val, enum_err = _safe_enum_name_value(val, val_t)
            if enum_err:
                return enum_err
            err = _scan_value(enum_val, depth + 1, check_callables=False, caller_names=caller_names)
            if err:
                return err
            raw_edict = _safe_instance_dict(val, val_t)
            if type(raw_edict) is dict:
                edict_view = _safe_str_dict_view(raw_edict)
                if edict_view is None:
                    return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                for ek in sorted(edict_view.keys()):
                    if ek in _RESERVED_ENUM_STORAGE_ATTRS or ek == "__weakref__":
                        continue
                    err = _scan_value(edict_view[ek], depth + 1, check_callables=False)
                    if err:
                        return err
            for sname, s_val in _safe_instance_slots(val, val_t):
                if sname in _RESERVED_ENUM_STORAGE_ATTRS:
                    continue
                err = _scan_value(s_val, depth + 1, check_callables=False)
                if err:
                    return err
            return _scan_value(val_t, depth + 1, check_callables=True, caller_names=caller_names)
        if val_t is functools.partial:
            kw_obj = val.keywords
            kw_vals: Tuple[Any, ...] = ()
            if type(kw_obj) is dict:
                kw_view = _safe_str_dict_view(kw_obj)
                if kw_view is None:
                    return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                kw_vals = tuple(kw_view[k] for k in sorted(kw_view.keys()))
            for part in (val.func, *val.args, *kw_vals):
                err = _scan_value(part, depth + 1, check_callables=True)
                if err:
                    return err
            return None
        if val_t is types.MethodType:
            err = _scan_value(val.__func__, depth + 1, check_callables=True)
            if err:
                return err
            return _scan_value(val.__self__, depth + 1, check_callables=False)
        if _is_type_in(val_t, (list, tuple, set, frozenset, collections.deque)):
            iter_fn = (
                list.__iter__ if val_t is list else
                tuple.__iter__ if val_t is tuple else
                set.__iter__ if val_t is set else
                frozenset.__iter__ if val_t is frozenset else
                collections.deque.__iter__
            )
            for item in iter_fn(val):
                err = _scan_value(item, depth + 1, check_callables=check_callables)
                if err:
                    return err
            return None
        if val_t is dict:
            for k, v in dict.items(val):
                err = _scan_value(k, depth + 1, check_callables=False)
                if err:
                    return err
                err = _scan_value(v, depth + 1, check_callables=check_callables)
                if err:
                    return err
            return None
        if val_t is types.MappingProxyType:
            backing = _safe_mappingproxy_dict(val)
            if backing is None:
                return "CALLABLE_CUSTOM_MAPPING_PROXY_FORBIDDEN"
            for k, v in dict.items(backing):
                err = _scan_value(k, depth + 1, check_callables=False)
                if err:
                    return err
                err = _scan_value(v, depth + 1, check_callables=check_callables)
                if err:
                    return err
            return None
        if val_t is types.CodeType:
            for seq in (val.co_names, val.co_varnames, val.co_freevars, val.co_cellvars):
                if type(seq) is not tuple or any(type(item) is not str for item in seq):
                    return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
            names = _collect_code_names(val)
            bad = sorted(names & _FORBIDDEN_CALLABLE_NAMES)
            if bad:
                return f"CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:{bad[0]}"
            if "modules" in names and "sys" in names:
                return "CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:sys.modules"
            return None
        if val_t is types.FunctionType:
            if not check_callables:
                return None
            code_obj = object.__getattribute__(val, "__code__")
            if type(code_obj) is types.CodeType:
                err = _scan_value(code_obj, depth + 1, check_callables=True)
                if err:
                    return err
                names = _collect_code_names(code_obj)
                str_consts = _collect_code_string_consts(code_obj)
                fn_caller_names = frozenset(names | str_consts)
                if "modules" in names:
                    fn_globals_m = object.__getattribute__(val, "__globals__")
                    if type(fn_globals_m) is dict:
                        for g_val in dict.values(fn_globals_m):
                            if type(g_val) is types.ModuleType:
                                gm_dict = object.__getattribute__(g_val, "__dict__")
                                if type(gm_dict) is dict:
                                    gm_view = _safe_str_dict_view(gm_dict)
                                    if gm_view is None:
                                        return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                                    raw_gnm = gm_view.get("__name__")
                                    if type(raw_gnm) is str and raw_gnm == "sys":
                                        return "CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:sys.modules"
            else:
                code_obj = None
                fn_caller_names = frozenset()
            for def_v in (object.__getattribute__(val, "__defaults__") or ()):
                err = _scan_value(def_v, depth + 1, check_callables=True, caller_names=fn_caller_names)
                if err:
                    return err
            raw_fn_mod = object.__getattribute__(val, "__module__")
            if raw_fn_mod is not None and type(raw_fn_mod) is not str:
                return "CALLABLE_CUSTOM_ATTRIBUTE_HOOK_FORBIDDEN:__module__"
            kw_d = object.__getattribute__(val, "__kwdefaults__")
            if type(kw_d) is dict:
                if _safe_namespace_str_keys(kw_d) is None:
                    return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                for kw_v in dict.values(kw_d):
                    err = _scan_value(kw_v, depth + 1, check_callables=True, caller_names=fn_caller_names)
                    if err:
                        return err
            freevars = tuple(getattr(code_obj, "co_freevars", ()) or ()) if code_obj is not None else ()
            for idx, cell in enumerate(object.__getattribute__(val, "__closure__") or ()):
                try:
                    cval = cell.cell_contents
                except ValueError as _cell_err:
                    _ = _cell_err
                    continue
                if "modules" in (_collect_code_names(code_obj) if code_obj is not None else set()):
                    fv_name = freevars[idx] if idx < len(freevars) else ""
                    if type(cval) is types.ModuleType:
                        cm_dict = object.__getattribute__(cval, "__dict__")
                        if type(cm_dict) is dict:
                            cm_view = _safe_str_dict_view(cm_dict)
                            if cm_view is None:
                                return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                            raw_cnm = cm_view.get("__name__")
                            if type(raw_cnm) is str and raw_cnm == "sys":
                                return "CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:sys.modules"
                    if fv_name == "sys" and cval is sys:
                        return "CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:sys.modules"
                err = _scan_value(cval, depth + 1, check_callables=True, caller_names=fn_caller_names)
                if err:
                    return err
            if code_obj is not None:
                fn_globals = object.__getattribute__(val, "__globals__")
                if type(fn_globals) is not dict:
                    return "CALLABLE_CUSTOM_GLOBALS_FORBIDDEN"
                fg_view = _safe_str_dict_view(fn_globals)
                if fg_view is None:
                    return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                gkeys = sorted(fg_view.keys())
                raw_builtins = fg_view.get("__builtins__", builtins)
                if raw_builtins is not builtins:
                    if not _is_type_in(type(raw_builtins), (dict, types.ModuleType)):
                        return "CALLABLE_CUSTOM_BUILTINS_FORBIDDEN"
                    if type(raw_builtins) is dict and _safe_str_dict_view(raw_builtins) is None:
                        return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                    if type(raw_builtins) is types.ModuleType:
                        rb_dict = object.__getattribute__(raw_builtins, "__dict__")
                        if type(rb_dict) is dict and _safe_str_dict_view(rb_dict) is None:
                            return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                for imp_name in sorted(_collect_code_import_names(code_obj)):
                    if imp_name == "mmap" or imp_name.startswith("mmap."):
                        return "CALLABLE_SHARED_MMAP_FORBIDDEN"
                    if imp_name == "importlib" or imp_name.startswith("importlib."):
                        return "CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:importlib"
                    if imp_name != "ctypes" and not imp_name.startswith("ctypes."):
                        imp_mod = _safe_sys_module_get(imp_name)
                        if imp_mod is not None:
                            err = _scan_value(
                                imp_mod,
                                depth + 1,
                                check_callables=False,
                                caller_names=fn_caller_names,
                            )
                            if err:
                                return err
                imp_builtin = _lookup_fn_builtin(fn_globals, "__import__")
                if imp_builtin is not _MISSING_GLOBAL_MARKER:
                    err = _scan_value(imp_builtin, depth + 1, check_callables=False, caller_names=fn_caller_names)
                    if err:
                        return err
                local_bound = (
                    set(getattr(code_obj, "co_varnames", ()) or ())
                    | set(freevars)
                    | set(getattr(code_obj, "co_cellvars", ()) or ())
                )
                for gname in sorted(fn_caller_names):
                    if gname in local_bound:
                        continue
                    if gname not in fg_view:
                        bval = _lookup_fn_builtin(fn_globals, gname)
                        if bval is not _MISSING_GLOBAL_MARKER:
                            err = _scan_value(bval, depth + 1, check_callables=False, caller_names=fn_caller_names)
                            if err:
                                return err
                        continue
                    gval = fg_view[gname]
                    gval_t = type(gval)
                    if gval_t is mmap.mmap or _has_base_in_mro(gval_t, mmap.mmap):
                        return "CALLABLE_SHARED_MMAP_FORBIDDEN"
                    if gval_t is memoryview:
                        mv_err = _check_memoryview_backing_error(gval)
                        if mv_err:
                            return mv_err
                    if _FFI_FORBIDDEN_TYPES and _has_base_in_mro(gval_t, _FFI_FORBIDDEN_TYPES):
                        return "CALLABLE_NATIVE_FFI_OBJECT_FORBIDDEN"
                    should_descend_fn = (
                        gval_t is types.FunctionType
                        and not _safe_fn_module(gval).startswith("kintsugi.")
                    )
                    err = _scan_value(
                        gval,
                        depth + 1,
                        check_callables=should_descend_fn,
                        caller_names=fn_caller_names,
                    )
                    if err:
                        return err
                for gname in gkeys:
                    if gname in fn_caller_names or gname.startswith("__"):
                        continue
                    gval = fg_view[gname]
                    gval_t = type(gval)
                    if gval_t is mmap.mmap or _has_base_in_mro(gval_t, mmap.mmap):
                        return "CALLABLE_SHARED_MMAP_FORBIDDEN"
                    if gval_t is memoryview:
                        mv_err = _check_memoryview_backing_error(gval)
                        if mv_err:
                            return mv_err
                    if (
                        _has_base_in_mro(gval_t, types.ModuleType)
                        or _has_base_in_mro(gval_t, type)
                        or callable(gval)
                    ):
                        continue
                    err = _scan_value(gval, depth + 1, check_callables=False)
                    if err:
                        return err
            return None
        if _has_base_in_mro(val_t, type):
            safety_err = _validate_class_preflight_safety(val)
            if safety_err:
                return safety_err
            for base in _safe_type_mro(val):
                if base is object:
                    continue
                base_mod = _safe_type_module(base)
                base_view = _safe_str_dict_view(_safe_type_dict(base))
                if base_view is None:
                    return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                if _is_stdlib_module_name(base_mod):
                    for k in sorted(base_view.keys()):
                        v = base_view[k]
                        vt = type(v)
                        if vt is mmap.mmap or _has_base_in_mro(vt, mmap.mmap):
                            return "CALLABLE_SHARED_MMAP_FORBIDDEN"
                        if vt is memoryview:
                            mv_err = _check_memoryview_backing_error(v)
                            if mv_err:
                                return mv_err
                        if _FFI_FORBIDDEN_TYPES and _has_base_in_mro(vt, _FFI_FORBIDDEN_TYPES):
                            return "CALLABLE_NATIVE_FFI_OBJECT_FORBIDDEN"
                        v_fn = vt is types.FunctionType
                        v_mod = _safe_fn_module(v) if v_fn else _safe_type_module(vt)
                        if not _is_stdlib_module_name(v_mod):
                            err = _scan_value(v, depth + 1, check_callables=v_fn, caller_names=caller_names)
                            if err:
                                return err
                    continue
                is_kintsugi_base = base_mod.startswith("kintsugi.")
                for k in sorted(base_view.keys()):
                    v = base_view[k]
                    if k in _SKIP_TYPE_METADATA_ATTRS:
                        continue
                    vt = type(v)
                    if vt is mmap.mmap or _has_base_in_mro(vt, mmap.mmap):
                        return "CALLABLE_SHARED_MMAP_FORBIDDEN"
                    if vt is memoryview:
                        mv_err = _check_memoryview_backing_error(v)
                        if mv_err:
                            return mv_err
                    if _FFI_FORBIDDEN_TYPES and _has_base_in_mro(vt, _FFI_FORBIDDEN_TYPES):
                        return "CALLABLE_NATIVE_FFI_OBJECT_FORBIDDEN"
                    if vt is property:
                        for prop_fn in (v.fget, v.fset, v.fdel):
                            if prop_fn is not None:
                                pf_own_kintsugi = (
                                    is_kintsugi_base
                                    and type(prop_fn) is types.FunctionType
                                    and _safe_fn_module(prop_fn) == base_mod
                                )
                                err = _scan_value(
                                    prop_fn, depth + 1, check_callables=(not pf_own_kintsugi), caller_names=caller_names
                                )
                                if err:
                                    return err
                        continue
                    if vt is functools.cached_property:
                        cp_dict = _safe_instance_dict(v, vt)
                        if type(cp_dict) is dict:
                            cp_view = _safe_str_dict_view(cp_dict)
                            if cp_view is None:
                                return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                            cp_fn = cp_view.get("func")
                        else:
                            cp_fn = None
                        if cp_fn is not None:
                            cp_own_kintsugi = (
                                is_kintsugi_base
                                and type(cp_fn) is types.FunctionType
                                and _safe_fn_module(cp_fn) == base_mod
                            )
                            err = _scan_value(
                                cp_fn, depth + 1, check_callables=(not cp_own_kintsugi), caller_names=caller_names
                            )
                            if err:
                                return err
                        continue
                    if _is_type_in(vt, (types.DynamicClassAttribute, _ENUM_PROPERTY_TYPE)):
                        dc_dict = _safe_instance_dict(v, vt)
                        if type(dc_dict) is dict:
                            dc_view = _safe_str_dict_view(dc_dict)
                            if dc_view is None:
                                return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
                            for p_attr in ("fget", "fset", "fdel"):
                                prop_fn = dc_view.get(p_attr)
                                if prop_fn is not None:
                                    pf_own_kintsugi = (
                                        is_kintsugi_base
                                        and type(prop_fn) is types.FunctionType
                                        and _safe_fn_module(prop_fn) == base_mod
                                    )
                                    err = _scan_value(
                                        prop_fn, depth + 1, check_callables=(not pf_own_kintsugi), caller_names=caller_names
                                    )
                                    if err:
                                        return err
                        continue
                    if _is_type_in(vt, (staticmethod, classmethod)):
                        inner_fn = v.__func__
                        if type(inner_fn) is types.FunctionType and _is_authentic_stdlib_class_helper(k, inner_fn):
                            err = _scan_stdlib_helper_fn(inner_fn, depth + 1, caller_names=caller_names)
                            if err:
                                return err
                            continue
                        in_own_kintsugi = (
                            is_kintsugi_base
                            and type(inner_fn) is types.FunctionType
                            and _safe_fn_module(inner_fn) == base_mod
                        )
                        err = _scan_value(
                            inner_fn, depth + 1, check_callables=(not in_own_kintsugi), caller_names=caller_names
                        )
                        if err:
                            return err
                        continue
                    if vt is types.FunctionType:
                        if _is_authentic_stdlib_class_helper(k, v):
                            err = _scan_stdlib_helper_fn(v, depth + 1, caller_names=caller_names)
                            if err:
                                return err
                            continue
                        fn_own_kintsugi = is_kintsugi_base and _safe_fn_module(v) == base_mod
                        err = _scan_value(
                            v, depth + 1, check_callables=(not fn_own_kintsugi), caller_names=caller_names
                        )
                        if err:
                            return err
                        continue
                    if not _is_skippable_runtime_obj(v):
                        err = _scan_value(v, depth + 1, check_callables=False, caller_names=caller_names)
                        if err:
                            return err
            return None

        safety_err = _validate_class_preflight_safety(val_t)
        if safety_err:
            return safety_err
        err = _scan_value(val_t, depth + 1, check_callables=True, caller_names=caller_names)
        if err:
            return err
        builtin_sub = _safe_builtin_subclass_payload(val)
        if builtin_sub is not None:
            sub_kind, sub_items = builtin_sub
            if sub_kind == "dict":
                for sk, sv in sub_items:
                    err = _scan_value(sk, depth + 1, check_callables=False)
                    if err:
                        return err
                    err = _scan_value(sv, depth + 1, check_callables=False)
                    if err:
                        return err
            elif sub_kind in {"list", "tuple", "set", "frozenset"}:
                for si in sub_items:
                    err = _scan_value(si, depth + 1, check_callables=False)
                    if err:
                        return err
        raw_dict = _safe_instance_dict(val, val_t)
        if type(raw_dict) is dict:
            rview = _safe_str_dict_view(raw_dict)
            if rview is None:
                return "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"
            for k in sorted(rview.keys()):
                if k == "__weakref__":
                    continue
                err = _scan_value(rview[k], depth + 1, check_callables=False)
                if err:
                    return err
        for _sname, s_val in _safe_instance_slots(val, val_t):
            err = _scan_value(s_val, depth + 1, check_callables=False)
            if err:
                return err
        return None

    return _scan_value(fn, 0, check_callables=True)


def _canonicalize_code_object(
    code_obj: types.CodeType,
    *,
    active_ancestors: Set[int],
    depth: int,
    budget: List[int],
    dag_memo: Optional[Dict[Tuple[int, FrozenSet[str]], Tuple[str, Any]]] = None,
    cycle_deps: Optional[Set[int]] = None,
) -> Dict[str, Any]:
    return {
        "__t__": "code",
        "co_code": code_obj.co_code.hex(),
        "co_names": list(getattr(code_obj, "co_names", ()) or ()),
        "co_varnames": list(getattr(code_obj, "co_varnames", ()) or ()),
        "co_freevars": list(getattr(code_obj, "co_freevars", ()) or ()),
        "co_cellvars": list(getattr(code_obj, "co_cellvars", ()) or ()),
        "co_argcount": int(getattr(code_obj, "co_argcount", 0)),
        "co_posonlyargcount": int(getattr(code_obj, "co_posonlyargcount", 0)),
        "co_kwonlyargcount": int(getattr(code_obj, "co_kwonlyargcount", 0)),
        "co_flags": int(getattr(code_obj, "co_flags", 0)),
        "co_consts": [
            _canonicalize_callable_state(
                c,
                active_ancestors=active_ancestors,
                depth=depth + 1,
                budget=budget,
                dag_memo=dag_memo,
                cycle_deps=cycle_deps,
            )
            for c in (getattr(code_obj, "co_consts", ()) or ())
        ],
    }


def _canonicalize_stdlib_func(
    fn_obj: types.FunctionType,
    *,
    active_ancestors: Set[int],
    depth: int,
    budget: List[int],
    caller_names: FrozenSet[str],
    allow_internal_kintsugi: bool = False,
    allow_stdlib_helper: bool = False,
    dag_memo: Optional[Dict[Tuple[int, FrozenSet[str]], Tuple[str, Any]]] = None,
    cycle_deps: Optional[Set[int]] = None,
) -> Any:
    """Serialize stdlib or internal-method bytecode/closures without crawling full module globals."""
    fn_mod = _safe_fn_module(fn_obj)
    if (
        not allow_stdlib_helper
        and not _is_stdlib_module_name(fn_mod)
        and not (allow_internal_kintsugi and fn_mod.startswith("kintsugi."))
    ):
        return _canonicalize_callable_state(
            fn_obj,
            active_ancestors=active_ancestors,
            depth=depth,
            budget=budget,
            caller_names=caller_names,
            dag_memo=dag_memo,
            cycle_deps=cycle_deps,
        )
    if depth > _MAX_CANONICAL_DEPTH or budget[0] <= 0:
        raise ValueError("CALLABLE_STATE_CANONICALIZATION_LIMIT_EXCEEDED")
    budget[0] -= 1
    code_obj = object.__getattribute__(fn_obj, "__code__")
    if type(code_obj) is not types.CodeType:
        code_obj = None
    freevars = tuple(getattr(code_obj, "co_freevars", ()) or ()) if code_obj is not None else ()
    closure_items: List[List[Any]] = []
    for idx, cell in enumerate(object.__getattribute__(fn_obj, "__closure__") or ()):
        fv_name = freevars[idx] if idx < len(freevars) else f"cell_{idx}"
        try:
            cval = cell.cell_contents
        except ValueError:
            closure_items.append([fv_name, {"__empty_cell__": True}])
        else:
            closure_items.append([
                fv_name,
                _canonicalize_callable_state(
                    cval,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=budget,
                    caller_names=caller_names,
                    dag_memo=dag_memo,
                    cycle_deps=cycle_deps,
                ),
            ])
    defaults = object.__getattribute__(fn_obj, "__defaults__")
    kwdefaults = object.__getattribute__(fn_obj, "__kwdefaults__")
    return {
        "__t__": (
            "stdlib_function"
            if (_is_stdlib_module_name(fn_mod) or allow_stdlib_helper)
            else "internal_method"
        ),
        "module": fn_mod,
        "qualname": _safe_fn_qualname(fn_obj),
        "code": (
            _canonicalize_code_object(
                code_obj,
                active_ancestors=active_ancestors,
                depth=depth + 1,
                budget=budget,
                dag_memo=dag_memo,
                cycle_deps=cycle_deps,
            )
            if code_obj is not None
            else ""
        ),
        "defaults": (
            _canonicalize_callable_state(
                defaults,
                active_ancestors=active_ancestors,
                depth=depth + 1,
                budget=budget,
                caller_names=caller_names,
                dag_memo=dag_memo,
                cycle_deps=cycle_deps,
            )
            if defaults is not None
            else None
        ),
        "kwdefaults": (
            _canonicalize_callable_state(
                kwdefaults,
                active_ancestors=active_ancestors,
                depth=depth + 1,
                budget=budget,
                caller_names=caller_names,
                dag_memo=dag_memo,
                cycle_deps=cycle_deps,
            )
            if kwdefaults is not None
            else None
        ),
        "closure": closure_items,
    }


def _canonicalize_stdlib_module(
    mod: types.ModuleType,
    *,
    caller_names: FrozenSet[str],
    active_ancestors: Set[int],
    depth: int,
    budget: List[int],
    dag_memo: Optional[Dict[Tuple[int, FrozenSet[str]], Tuple[str, Any]]] = None,
    cycle_deps: Optional[Set[int]] = None,
) -> Dict[str, Any]:
    """Bind referenced stdlib attributes and detect monkeypatched foreign functions/objects."""
    mod_dict = object.__getattribute__(mod, "__dict__")
    if type(mod_dict) is dict:
        mod_view = _safe_str_dict_view(mod_dict)
        if mod_view is None:
            raise ValueError("CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN")
    else:
        mod_view = {}
    raw_mod_name = mod_view.get("__name__", "")
    mod_name = raw_mod_name if type(raw_mod_name) is str else ""
    mod_keys = sorted(mod_view.keys())
    bound_attrs: Dict[str, Any] = {}
    foreign_patches: Dict[str, Any] = {}

    for k in sorted(caller_names):
        if k.startswith("__") or k not in mod_view:
            continue
        v = mod_view[k]
        if v is sys.modules:
            bound_attrs[k] = {"__t__": "sys_modules_ref"}
        elif mod_name == "sys" and k == "argv":
            bound_attrs[k] = {"__t__": "sys_argv_ref"}
        elif _is_skippable_runtime_obj(v):
            bound_attrs[k] = _canonicalize_callable_state(
                v,
                active_ancestors=active_ancestors,
                depth=depth + 1,
                budget=budget,
                caller_names=caller_names,
                dag_memo=dag_memo,
                cycle_deps=cycle_deps,
            )
        elif type(v) is types.FunctionType:
            bound_attrs[k] = _canonicalize_stdlib_func(
                v,
                active_ancestors=active_ancestors,
                depth=depth + 1,
                budget=budget,
                caller_names=caller_names,
                dag_memo=dag_memo,
                cycle_deps=cycle_deps,
            )
        else:
            bound_attrs[k] = _canonicalize_callable_state(
                v,
                active_ancestors=active_ancestors,
                depth=depth + 1,
                budget=budget,
                caller_names=caller_names,
                dag_memo=dag_memo,
                cycle_deps=cycle_deps,
            )

    for ks in mod_keys:
        if (ks.startswith("__") and ks != "__getattr__") or ks in bound_attrs:
            continue
        v = mod_view[ks]
        if _is_skippable_runtime_obj(v) or v is sys.modules or (mod_name == "sys" and ks == "argv"):
            continue
        vt = type(v)
        is_foreign = (
            vt is mmap.mmap
            or _has_base_in_mro(vt, mmap.mmap)
            or (_FFI_FORBIDDEN_TYPES and _has_base_in_mro(vt, _FFI_FORBIDDEN_TYPES))
            or (vt is memoryview and _check_memoryview_backing_error(v) is not None)
            or (vt is types.FunctionType and not _is_stdlib_module_name(_safe_fn_module(v)))
            or (_has_base_in_mro(vt, type) and not _is_stdlib_module_name(_safe_type_module(v)))
            or _is_type_in(vt, (functools.partial, types.MethodType))
            or (
                not _is_type_in(
                    vt,
                    (
                        type(None), bool, int, float, str, bytes, bytearray, memoryview,
                        tuple, list, dict, set, frozenset, types.ModuleType, *_STDLIB_BUILTIN_TYPES,
                    ),
                )
                and not _is_stdlib_module_name(_safe_type_module(vt))
            )
        )
        if is_foreign:
            foreign_patches[ks] = _canonicalize_callable_state(
                v,
                active_ancestors=active_ancestors,
                depth=depth + 1,
                budget=budget,
                caller_names=caller_names,
                dag_memo=dag_memo,
                cycle_deps=cycle_deps,
            )

    return {
        "__t__": "stdlib_module",
        "name": mod_name,
        "bound_attrs": bound_attrs,
        "foreign_patches": foreign_patches,
    }


def _canonicalize_dict_pairs(
    pairs: Sequence[Tuple[Any, Any]],
    *,
    active_ancestors: Set[int],
    depth: int,
    budget: List[int],
    caller_names: FrozenSet[str],
    dag_memo: Optional[Dict[Tuple[int, FrozenSet[str]], Tuple[str, Any]]] = None,
    cycle_deps: Optional[Set[int]] = None,
    type_tag: str = "dict",
) -> Dict[str, Any]:
    """Canonicalize `(k, v)` pairs linearly without re-hashing or calling `dict(pairs)`."""
    if depth > _MAX_CANONICAL_DEPTH or budget[0] <= 0:
        raise ValueError("CALLABLE_STATE_CANONICALIZATION_LIMIT_EXCEEDED")
    budget[0] -= 1
    items = []
    for k, v in pairs:
        ck = _canonicalize_callable_state(
            k,
            active_ancestors=active_ancestors,
            depth=depth + 1,
            budget=budget,
            caller_names=caller_names,
            dag_memo=dag_memo,
            cycle_deps=cycle_deps,
        )
        cv = _canonicalize_callable_state(
            v,
            active_ancestors=active_ancestors,
            depth=depth + 1,
            budget=budget,
            caller_names=caller_names,
            dag_memo=dag_memo,
            cycle_deps=cycle_deps,
        )
        items.append((sha256_digest(ck), ck, cv))
    items.sort(key=lambda row: row[0])
    return {"__t__": type_tag, "v": [[ck, cv] for _, ck, cv in items]}


def _canonicalize_callable_state(
    obj: Any,
    *,
    active_ancestors: Set[int],
    depth: int = 0,
    budget: Optional[List[int]] = None,
    caller_names: FrozenSet[str] = frozenset(),
    dag_memo: Optional[Dict[Tuple[int, FrozenSet[str]], Tuple[str, Any]]] = None,
    cycle_deps: Optional[Set[int]] = None,
) -> Any:
    """Deterministically serialize bytecode plus closure, default, MRO, and dependency state (zero user-hook execution)."""
    rem_budget = budget if budget is not None else [_MAX_CANONICAL_BUDGET]
    memo = dag_memo if dag_memo is not None else {}
    if depth > _MAX_CANONICAL_DEPTH or rem_budget[0] <= 0:
        raise ValueError("CALLABLE_STATE_CANONICALIZATION_LIMIT_EXCEEDED")
    rem_budget[0] -= 1

    if obj is None:
        return None
    if obj is Ellipsis:
        return {"__t__": "ellipsis"}
    if obj is NotImplemented:
        return {"__t__": "not_implemented"}
    obj_t = type(obj)
    if obj_t is object:
        return {"__t__": "object_sentinel"}
    if obj_t is bool:
        return {"__t__": "bool", "v": obj}
    if obj_t is int:
        return {"__t__": "int", "v": obj}
    if obj_t is float:
        return {"__t__": "float", "v": obj if math.isfinite(obj) else repr(obj)}
    if obj_t is str:
        return {"__t__": "str", "v": obj}
    if obj_t is bytes or obj_t is bytearray:
        raw = bytes(obj)
        return {"__t__": obj_t.__name__, "sha256": hashlib.sha256(raw).hexdigest(), "len": len(raw)}
    if obj_t is memoryview:
        if _check_memoryview_backing_error(obj) == "CALLABLE_SHARED_MMAP_FORBIDDEN":
            return {"__t__": "mmap_forbidden"}
        try:
            _mv_alive = obj.obj
        except ValueError:
            return {"__t__": "memoryview_released"}
        _ = _mv_alive
        raw = bytes(obj)
        return {"__t__": "memoryview", "sha256": hashlib.sha256(raw).hexdigest(), "len": len(raw)}
    if obj_t is Decimal:
        return {"__t__": "decimal", "v": str(obj)}
    if _is_type_in(obj_t, (PurePath, PurePosixPath, PureWindowsPath, Path, PosixPath, WindowsPath)):
        return {"__t__": "path", "v": str(obj)}
    if obj_t is re.Pattern:
        return {"__t__": "re.Pattern", "pattern": obj.pattern, "flags": int(obj.flags)}
    if obj_t is mmap.mmap or _has_base_in_mro(obj_t, mmap.mmap):
        return {"__t__": "mmap_forbidden"}
    if _FFI_FORBIDDEN_TYPES and _has_base_in_mro(obj_t, _FFI_FORBIDDEN_TYPES):
        return {
            "__t__": "ctypes_ffi",
            "cls": f"{_safe_type_module(obj_t)}.{_safe_type_qualname(obj_t)}",
        }
    if _is_skippable_runtime_obj(obj):
        return {
            "__t__": "runtime_handle",
            "cls": f"{_safe_type_module(obj_t)}.{_safe_type_qualname(obj_t)}",
        }
    if _is_type_in(obj_t, _STDLIB_BUILTIN_TYPES):
        raw_mod_name = getattr(obj, "__module__", None)
        mod_name = raw_mod_name if type(raw_mod_name) is str else ""
        raw_qual = getattr(obj, "__qualname__", None)
        raw_name = getattr(obj, "__name__", None)
        nm = raw_qual if type(raw_qual) is str and raw_qual else (raw_name if type(raw_name) is str and raw_name else obj_t.__name__)
        entry: Dict[str, Any] = {"__t__": "stdlib_or_builtin", "mod": mod_name, "name": nm}
        bound_self = getattr(obj, "__self__", None)
        if (
            bound_self is not None
            and type(bound_self) is not types.ModuleType
            and not _is_skippable_runtime_obj(bound_self)
        ):
            entry["self"] = _canonicalize_callable_state(
                bound_self,
                active_ancestors=active_ancestors,
                depth=depth + 1,
                budget=rem_budget,
                caller_names=caller_names,
                dag_memo=memo,
                cycle_deps=cycle_deps,
            )
        return entry

    oid = id(obj)
    if oid in active_ancestors:
        if cycle_deps is not None:
            cycle_deps.add(oid)
        return {"__t__": "cycle", "type": _safe_type_qualname(obj_t)}
    is_stdlib_mod = obj_t is types.ModuleType and _is_stdlib_module(obj)
    memo_key = (oid, caller_names)
    if not is_stdlib_mod and memo_key in memo:
        return {"__t__": "hashed_node", "sha256": memo[memo_key][0]}

    local_cycles: Set[int] = set()

    def _canonicalize_compound() -> Any:
        if _has_base_in_mro(obj_t, Enum):
            safety_err = _validate_class_preflight_safety(obj_t)
            if safety_err:
                raise ValueError(safety_err)
            raw_ename, raw_eval, enum_err = _safe_enum_name_value(obj, obj_t)
            if enum_err:
                raise ValueError(enum_err)
            extra_state: Dict[str, Any] = {}
            raw_edict = _safe_instance_dict(obj, obj_t)
            if type(raw_edict) is dict:
                edict_view = _safe_str_dict_view(raw_edict)
                if edict_view is None:
                    raise ValueError("CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN")
                for ek in sorted(edict_view.keys()):
                    if ek in _RESERVED_ENUM_STORAGE_ATTRS or ek == "__weakref__":
                        continue
                    extra_state[ek] = _canonicalize_callable_state(
                        edict_view[ek],
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        caller_names=caller_names,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
            for sname, sval in _safe_instance_slots(obj, obj_t):
                if sname in _RESERVED_ENUM_STORAGE_ATTRS:
                    continue
                extra_state[sname] = _canonicalize_callable_state(
                    sval,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                )
            builtin_sub = _safe_builtin_subclass_payload(obj)
            encoded_sub = None
            if builtin_sub is not None:
                sub_kind, sub_items = builtin_sub
                encoded_sub = {
                    "kind": sub_kind,
                    "val": (
                        _canonicalize_dict_pairs(
                            sub_items,
                            active_ancestors=active_ancestors,
                            depth=depth + 1,
                            budget=rem_budget,
                            caller_names=caller_names,
                            dag_memo=memo,
                            cycle_deps=local_cycles,
                        )
                        if sub_kind == "dict"
                        else _canonicalize_callable_state(
                            sub_items,
                            active_ancestors=active_ancestors,
                            depth=depth + 1,
                            budget=rem_budget,
                            caller_names=caller_names,
                            dag_memo=memo,
                            cycle_deps=local_cycles,
                        )
                    ),
                }
            return {
                "__t__": "enum",
                "cls": f"{_safe_type_module(obj_t)}.{_safe_type_qualname(obj_t)}",
                "type_def": _canonicalize_callable_state(
                    obj_t,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                ),
                "name": raw_ename,
                "v": _canonicalize_callable_state(
                    raw_eval,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                ),
                "extra": extra_state,
                "builtin_payload": encoded_sub,
            }
        if obj_t is types.ModuleType or _has_base_in_mro(obj_t, types.ModuleType):
            if obj_t is not types.ModuleType:
                safety_err = _validate_class_preflight_safety(obj_t)
                if safety_err:
                    raise ValueError(safety_err)
            if _is_stdlib_module(obj):
                return _canonicalize_stdlib_module(
                    obj,
                    caller_names=caller_names,
                    active_ancestors=active_ancestors,
                    depth=depth,
                    budget=rem_budget,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                )
            mod_dict = object.__getattribute__(obj, "__dict__") if obj_t is types.ModuleType else _safe_instance_dict(obj, obj_t)
            attrs: Dict[str, Any] = {}
            raw_mname: Any = ""
            if type(mod_dict) is dict:
                mod_view = _safe_str_dict_view(mod_dict)
                if mod_view is None:
                    raise ValueError("CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN")
                raw_mname = mod_view.get("__name__", "")
                for k in sorted(mod_view.keys()):
                    if k.startswith("__"):
                        continue
                    v = mod_view[k]
                    if _has_base_in_mro(type(v), types.ModuleType) and _is_stdlib_module(v):
                        continue
                    if _is_skippable_runtime_obj(v):
                        continue
                    attrs[k] = _canonicalize_callable_state(
                        v,
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        caller_names=caller_names,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
            return {"__t__": "user_module", "name": raw_mname if type(raw_mname) is str else "", "attrs": attrs}
        if obj_t is types.CodeType:
            return _canonicalize_code_object(
                obj,
                active_ancestors=active_ancestors,
                depth=depth,
                budget=rem_budget,
                dag_memo=memo,
                cycle_deps=local_cycles,
            )
        if obj_t is functools.partial:
            kw_obj = obj.keywords
            kw_items: Dict[str, Any] = {}
            if type(kw_obj) is dict:
                kw_view = _safe_str_dict_view(kw_obj)
                if kw_view is None:
                    raise ValueError("CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN")
                for k in sorted(kw_view.keys()):
                    kw_items[k] = _canonicalize_callable_state(
                        kw_view[k],
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        caller_names=caller_names,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
            return {
                "__t__": "partial",
                "func": _canonicalize_callable_state(
                    obj.func,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                ),
                "args": [
                    _canonicalize_callable_state(
                        x,
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        caller_names=caller_names,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
                    for x in obj.args
                ],
                "keywords": kw_items,
            }
        if obj_t is types.MethodType:
            return {
                "__t__": "method",
                "func": _canonicalize_callable_state(
                    obj.__func__,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                ),
                "self": _canonicalize_callable_state(
                    obj.__self__,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                ),
            }
        if obj_t is slice:
            return {
                "__t__": "slice",
                "start": _canonicalize_callable_state(
                    obj.start,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                ),
                "stop": _canonicalize_callable_state(
                    obj.stop,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                ),
                "step": _canonicalize_callable_state(
                    obj.step,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                ),
            }
        if obj_t is collections.deque:
            return {
                "__t__": "deque",
                "maxlen": obj.maxlen,
                "v": [
                    _canonicalize_callable_state(
                        x,
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        caller_names=caller_names,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
                    for x in collections.deque.__iter__(obj)
                ],
            }
        if obj_t is types.MappingProxyType:
            backing = _safe_mappingproxy_dict(obj)
            if backing is None:
                raise ValueError("CALLABLE_CUSTOM_MAPPING_PROXY_FORBIDDEN")
            mp_items = []
            for k, v in dict.items(backing):
                ck = _canonicalize_callable_state(
                    k,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                )
                cv = _canonicalize_callable_state(
                    v,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                )
                mp_items.append((sha256_digest(ck), ck, cv))
            mp_items.sort(key=lambda row: row[0])
            return {"__t__": "mappingproxy", "v": [[ck, cv] for _, ck, cv in mp_items]}
        if obj_t is tuple:
            return {
                "__t__": "tuple",
                "v": [
                    _canonicalize_callable_state(
                        x,
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        caller_names=caller_names,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
                    for x in tuple.__iter__(obj)
                ],
            }
        if obj_t is list:
            return {
                "__t__": "list",
                "v": [
                    _canonicalize_callable_state(
                        x,
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        caller_names=caller_names,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
                    for x in list.__iter__(obj)
                ],
            }
        if obj_t is set or obj_t is frozenset:
            iter_fn = frozenset.__iter__ if obj_t is frozenset else set.__iter__
            encoded = [
                _canonicalize_callable_state(
                    x,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                )
                for x in iter_fn(obj)
            ]
            encoded.sort(key=lambda item: sha256_digest(item))
            return {"__t__": obj_t.__name__, "v": encoded}
        if obj_t is dict:
            items = []
            for k, v in dict.items(obj):
                ck = _canonicalize_callable_state(
                    k,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                )
                cv = _canonicalize_callable_state(
                    v,
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                )
                items.append((sha256_digest(ck), ck, cv))
            items.sort(key=lambda row: row[0])
            return {"__t__": "dict", "v": [[ck, cv] for _, ck, cv in items]}
        if _has_base_in_mro(obj_t, type):
            safety_err = _validate_class_preflight_safety(obj)
            if safety_err:
                raise ValueError(safety_err)
            mod = _safe_type_module(obj)
            qual = f"{mod}.{_safe_type_qualname(obj)}"
            if _is_stdlib_module_name(mod):
                cls_view = _safe_str_dict_view(_safe_type_dict(obj))
                if cls_view is None:
                    raise ValueError("CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN")
                patched_cls_attrs: Dict[str, Any] = {}
                for k in sorted(cls_view.keys()):
                    v = cls_view[k]
                    vt = type(v)
                    v_mod = _safe_fn_module(v) if vt is types.FunctionType else _safe_type_module(vt)
                    if not _is_stdlib_module_name(v_mod) and not _is_type_in(vt, _STDLIB_BUILTIN_TYPES):
                        patched_cls_attrs[k] = _canonicalize_callable_state(
                            v,
                            active_ancestors=active_ancestors,
                            depth=depth + 1,
                            budget=rem_budget,
                            caller_names=caller_names,
                            dag_memo=memo,
                            cycle_deps=local_cycles,
                        )
                return {"__t__": "stdlib_type", "qual": qual, "patched": patched_cls_attrs}
            mro_entries: List[Dict[str, Any]] = []
            for base in _safe_type_mro(obj):
                if base is object:
                    continue
                base_mod = _safe_type_module(base)
                base_qual = f"{base_mod}.{_safe_type_qualname(base)}"
                base_view = _safe_str_dict_view(_safe_type_dict(base))
                if base_view is None:
                    raise ValueError("CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN")
                if _is_stdlib_module_name(base_mod):
                    base_patched: Dict[str, Any] = {}
                    for k in sorted(base_view.keys()):
                        v = base_view[k]
                        vt = type(v)
                        v_mod = _safe_fn_module(v) if vt is types.FunctionType else _safe_type_module(vt)
                        if not _is_stdlib_module_name(v_mod) and not _is_type_in(vt, _STDLIB_BUILTIN_TYPES):
                            base_patched[k] = _canonicalize_callable_state(
                                v,
                                active_ancestors=active_ancestors,
                                depth=depth + 1,
                                budget=rem_budget,
                                caller_names=caller_names,
                                dag_memo=memo,
                                cycle_deps=local_cycles,
                            )
                    mro_entries.append({"__t__": "stdlib_base", "qual": base_qual, "patched": base_patched})
                    continue
                is_internal_kintsugi = base_mod.startswith("kintsugi.")
                attrs: Dict[str, Any] = {}
                for k in sorted(base_view.keys()):
                    v = base_view[k]
                    ks = k
                    if ks in _SKIP_TYPE_METADATA_ATTRS:
                        continue
                    if _is_skippable_runtime_obj(v):
                        continue
                    vt = type(v)
                    if _is_type_in(vt, (staticmethod, classmethod)):
                        inner_fn = v.__func__
                        if type(inner_fn) is types.FunctionType and _is_authentic_stdlib_class_helper(ks, inner_fn):
                            fn_state = _canonicalize_stdlib_func(
                                inner_fn,
                                active_ancestors=active_ancestors,
                                depth=depth + 1,
                                budget=rem_budget,
                                caller_names=caller_names,
                                allow_stdlib_helper=True,
                                dag_memo=memo,
                                cycle_deps=local_cycles,
                            )
                        elif (
                            is_internal_kintsugi
                            and type(inner_fn) is types.FunctionType
                            and _safe_fn_module(inner_fn) == base_mod
                        ):
                            fn_state = _canonicalize_stdlib_func(
                                inner_fn,
                                active_ancestors=active_ancestors,
                                depth=depth + 1,
                                budget=rem_budget,
                                caller_names=caller_names,
                                allow_internal_kintsugi=True,
                                dag_memo=memo,
                                cycle_deps=local_cycles,
                            )
                        else:
                            fn_state = _canonicalize_callable_state(
                                inner_fn,
                                active_ancestors=active_ancestors,
                                depth=depth + 1,
                                budget=rem_budget,
                                caller_names=caller_names,
                                dag_memo=memo,
                                cycle_deps=local_cycles,
                            )
                        attrs[ks] = {"__t__": vt.__name__, "func": fn_state}
                        continue
                    if vt is property:
                        prop_map: Dict[str, Any] = {"__t__": "property"}
                        for p_key, p_fn in (("fget", v.fget), ("fset", v.fset), ("fdel", v.fdel)):
                            if p_fn is None:
                                prop_map[p_key] = None
                            elif (
                                is_internal_kintsugi
                                and type(p_fn) is types.FunctionType
                                and _safe_fn_module(p_fn) == base_mod
                            ):
                                prop_map[p_key] = _canonicalize_stdlib_func(
                                    p_fn,
                                    active_ancestors=active_ancestors,
                                    depth=depth + 1,
                                    budget=rem_budget,
                                    caller_names=caller_names,
                                    allow_internal_kintsugi=True,
                                    dag_memo=memo,
                                    cycle_deps=local_cycles,
                                )
                            else:
                                prop_map[p_key] = _canonicalize_callable_state(
                                    p_fn,
                                    active_ancestors=active_ancestors,
                                    depth=depth + 1,
                                    budget=rem_budget,
                                    caller_names=caller_names,
                                    dag_memo=memo,
                                    cycle_deps=local_cycles,
                                )
                        attrs[ks] = prop_map
                        continue
                    if vt is functools.cached_property:
                        cp_dict = _safe_instance_dict(v, vt)
                        if type(cp_dict) is dict:
                            cp_view = _safe_str_dict_view(cp_dict)
                            if cp_view is None:
                                raise ValueError("CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN")
                            cp_fn = cp_view.get("func")
                            raw_aname = cp_view.get("attrname")
                        else:
                            cp_fn = None
                            raw_aname = None
                        if (
                            is_internal_kintsugi
                            and type(cp_fn) is types.FunctionType
                            and _safe_fn_module(cp_fn) == base_mod
                        ):
                            cp_state = _canonicalize_stdlib_func(
                                cp_fn,
                                active_ancestors=active_ancestors,
                                depth=depth + 1,
                                budget=rem_budget,
                                caller_names=caller_names,
                                allow_internal_kintsugi=True,
                                dag_memo=memo,
                                cycle_deps=local_cycles,
                            )
                        else:
                            cp_state = _canonicalize_callable_state(
                                cp_fn,
                                active_ancestors=active_ancestors,
                                depth=depth + 1,
                                budget=rem_budget,
                                caller_names=caller_names,
                                dag_memo=memo,
                                cycle_deps=local_cycles,
                            )
                        attrs[ks] = {
                            "__t__": "cached_property",
                            "attrname": raw_aname if type(raw_aname) is str else None,
                            "func": cp_state,
                        }
                        continue
                    if _is_type_in(vt, (types.DynamicClassAttribute, _ENUM_PROPERTY_TYPE)):
                        dc_dict = _safe_instance_dict(v, vt)
                        if type(dc_dict) is dict:
                            dc_view = _safe_str_dict_view(dc_dict)
                            if dc_view is None:
                                raise ValueError("CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN")
                        else:
                            dc_view = None
                        dc_map: Dict[str, Any] = {"__t__": vt.__name__}
                        for p_key in ("fget", "fset", "fdel"):
                            p_fn = dc_view.get(p_key) if dc_view is not None else None
                            if p_fn is None:
                                dc_map[p_key] = None
                            elif (
                                is_internal_kintsugi
                                and type(p_fn) is types.FunctionType
                                and _safe_fn_module(p_fn) == base_mod
                            ):
                                dc_map[p_key] = _canonicalize_stdlib_func(
                                    p_fn,
                                    active_ancestors=active_ancestors,
                                    depth=depth + 1,
                                    budget=rem_budget,
                                    caller_names=caller_names,
                                    allow_internal_kintsugi=True,
                                    dag_memo=memo,
                                    cycle_deps=local_cycles,
                                )
                            else:
                                dc_map[p_key] = _canonicalize_callable_state(
                                    p_fn,
                                    active_ancestors=active_ancestors,
                                    depth=depth + 1,
                                    budget=rem_budget,
                                    caller_names=caller_names,
                                    dag_memo=memo,
                                    cycle_deps=local_cycles,
                                )
                        attrs[ks] = dc_map
                        continue
                    if _is_type_in(vt, (types.GetSetDescriptorType, types.MemberDescriptorType)):
                        attrs[ks] = {"__t__": vt.__name__, "name": ks}
                        continue
                    if vt is types.FunctionType and _is_authentic_stdlib_class_helper(ks, v):
                        attrs[ks] = _canonicalize_stdlib_func(
                            v,
                            active_ancestors=active_ancestors,
                            depth=depth + 1,
                            budget=rem_budget,
                            caller_names=caller_names,
                            allow_stdlib_helper=True,
                            dag_memo=memo,
                            cycle_deps=local_cycles,
                        )
                        continue
                    if vt is types.FunctionType and is_internal_kintsugi and _safe_fn_module(v) == base_mod:
                        attrs[ks] = _canonicalize_stdlib_func(
                            v,
                            active_ancestors=active_ancestors,
                            depth=depth + 1,
                            budget=rem_budget,
                            caller_names=caller_names,
                            allow_internal_kintsugi=True,
                            dag_memo=memo,
                            cycle_deps=local_cycles,
                        )
                        continue
                    attrs[ks] = _canonicalize_callable_state(
                        v,
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        caller_names=caller_names,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
                mro_entries.append({"__t__": "user_base", "qual": base_qual, "attrs": attrs})
            return {"__t__": "user_type", "qual": qual, "mro": mro_entries}
        if obj_t is types.FunctionType:
            code_obj = object.__getattribute__(obj, "__code__")
            if type(code_obj) is not types.CodeType:
                code_obj = None
            freevars = tuple(getattr(code_obj, "co_freevars", ()) or ()) if code_obj is not None else ()
            ref_names = (
                frozenset(_collect_code_names(code_obj) | _collect_code_string_consts(code_obj))
                if code_obj is not None
                else caller_names
            )
            cells = tuple(object.__getattribute__(obj, "__closure__") or ())
            closure_items: List[List[Any]] = []
            for idx, cell in enumerate(cells):
                fv_name = freevars[idx] if idx < len(freevars) else f"cell_{idx}"
                try:
                    cell_val = cell.cell_contents
                except ValueError:
                    cell_val = _EMPTY_CELL_MARKER
                if cell_val is _EMPTY_CELL_MARKER:
                    closure_items.append([fv_name, {"__empty_cell__": True}])
                else:
                    closure_items.append([
                        fv_name,
                        _canonicalize_callable_state(
                            cell_val,
                            active_ancestors=active_ancestors,
                            depth=depth + 1,
                            budget=rem_budget,
                            caller_names=ref_names,
                            dag_memo=memo,
                            cycle_deps=local_cycles,
                        ),
                    ])
            fn_globals = object.__getattribute__(obj, "__globals__")
            if type(fn_globals) is not dict:
                raise ValueError("CALLABLE_CUSTOM_GLOBALS_FORBIDDEN")
            fg_view = _safe_str_dict_view(fn_globals)
            if fg_view is None:
                raise ValueError("CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN")
            gkeys = sorted(fg_view.keys())
            raw_fn_mod = object.__getattribute__(obj, "__module__")
            if raw_fn_mod is not None and type(raw_fn_mod) is not str:
                raise ValueError("CALLABLE_CUSTOM_ATTRIBUTE_HOOK_FORBIDDEN:__module__")
            raw_builtins = fg_view.get("__builtins__", builtins)
            if raw_builtins is not builtins:
                if not _is_type_in(type(raw_builtins), (dict, types.ModuleType)):
                    raise ValueError("CALLABLE_CUSTOM_BUILTINS_FORBIDDEN")
                if type(raw_builtins) is dict and _safe_str_dict_view(raw_builtins) is None:
                    raise ValueError("CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN")
                if type(raw_builtins) is types.ModuleType:
                    rb_dict = object.__getattribute__(raw_builtins, "__dict__")
                    if type(rb_dict) is dict and _safe_str_dict_view(rb_dict) is None:
                        raise ValueError("CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN")
            local_bound = (
                set(getattr(code_obj, "co_varnames", ()) or ())
                | set(freevars)
                | set(getattr(code_obj, "co_cellvars", ()) or ())
            )
            global_items: Dict[str, Any] = {}
            builtin_items: Dict[str, Any] = {}
            imported_modules: Dict[str, Any] = {}
            if code_obj is not None:
                imp_names = _collect_code_import_names(code_obj)
                if imp_names:
                    imp_fn = _lookup_fn_builtin(fn_globals, "__import__")
                    if imp_fn is not _MISSING_GLOBAL_MARKER:
                        builtin_items["__import__"] = _canonicalize_callable_state(
                            imp_fn,
                            active_ancestors=active_ancestors,
                            depth=depth + 1,
                            budget=rem_budget,
                            caller_names=ref_names,
                            dag_memo=memo,
                            cycle_deps=local_cycles,
                        )
                    for imp_name in sorted(imp_names):
                        imp_mod = _safe_sys_module_get(imp_name)
                        if imp_mod is not None and _has_base_in_mro(type(imp_mod), types.ModuleType):
                            if _is_stdlib_module(imp_mod):
                                imported_modules[imp_name] = _canonicalize_stdlib_module(
                                    imp_mod,
                                    caller_names=ref_names,
                                    active_ancestors=active_ancestors,
                                    depth=depth + 1,
                                    budget=rem_budget,
                                    dag_memo=memo,
                                    cycle_deps=local_cycles,
                                )
                            else:
                                imported_modules[imp_name] = _canonicalize_callable_state(
                                    imp_mod,
                                    active_ancestors=active_ancestors,
                                    depth=depth + 1,
                                    budget=rem_budget,
                                    caller_names=ref_names,
                                    dag_memo=memo,
                                    cycle_deps=local_cycles,
                                )
                        else:
                            imported_modules[imp_name] = {"__t__": "unloaded_module", "name": imp_name}
                for gname in sorted(ref_names):
                    if gname in local_bound:
                        continue
                    if gname in fg_view:
                        gval = fg_view[gname]
                        if _is_skippable_runtime_obj(gval):
                            continue
                        if _has_base_in_mro(type(gval), types.ModuleType) and _is_stdlib_module(gval):
                            global_items[gname] = _canonicalize_stdlib_module(
                                gval,
                                caller_names=ref_names,
                                active_ancestors=active_ancestors,
                                depth=depth + 1,
                                budget=rem_budget,
                                dag_memo=memo,
                                cycle_deps=local_cycles,
                            )
                            continue
                        global_items[gname] = _canonicalize_callable_state(
                            gval,
                            active_ancestors=active_ancestors,
                            depth=depth + 1,
                            budget=rem_budget,
                            caller_names=ref_names,
                            dag_memo=memo,
                            cycle_deps=local_cycles,
                        )
                    else:
                        bval = _lookup_fn_builtin(fn_globals, gname)
                        if bval is not _MISSING_GLOBAL_MARKER and not _has_base_in_mro(type(bval), types.ModuleType):
                            builtin_items[gname] = _canonicalize_callable_state(
                                bval,
                                active_ancestors=active_ancestors,
                                depth=depth + 1,
                                budget=rem_budget,
                                caller_names=ref_names,
                                dag_memo=memo,
                                cycle_deps=local_cycles,
                            )
                for gname in gkeys:
                    if gname in global_items or gname.startswith("__"):
                        continue
                    gval = fg_view[gname]
                    gval_t = type(gval)
                    if _is_type_in(gval_t, _STDLIB_BUILTIN_TYPES) or _is_skippable_runtime_obj(gval):
                        continue
                    if _has_base_in_mro(gval_t, types.ModuleType):
                        if _is_stdlib_module(gval):
                            continue
                    elif _has_base_in_mro(gval_t, type) or callable(gval):
                        continue
                    global_items[gname] = _canonicalize_callable_state(
                        gval,
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        caller_names=ref_names,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
            defaults = object.__getattribute__(obj, "__defaults__")
            kwdefaults = object.__getattribute__(obj, "__kwdefaults__")
            return {
                "__t__": "function",
                "module": _safe_fn_module(obj),
                "qualname": _safe_fn_qualname(obj),
                "code": (
                    _canonicalize_code_object(
                        code_obj,
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
                    if code_obj is not None
                    else ""
                ),
                "defaults": (
                    _canonicalize_callable_state(
                        defaults,
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        caller_names=ref_names,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
                    if defaults is not None
                    else None
                ),
                "kwdefaults": (
                    _canonicalize_callable_state(
                        kwdefaults,
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        caller_names=ref_names,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
                    if kwdefaults is not None
                    else None
                ),
                "closure": closure_items,
                "globals": global_items,
                "builtins": builtin_items,
                "imports": imported_modules,
            }

        safety_err = _validate_class_preflight_safety(obj_t)
        if safety_err:
            raise ValueError(safety_err)
        cls_mod = _safe_type_module(obj_t)
        qual = f"{cls_mod}.{_safe_type_qualname(obj_t)}"
        if _is_type_in(obj_t, _SAFE_STDLIB_REPR_TYPES):
            return {"__t__": "stdlib_obj", "qual": qual, "repr": repr(obj)}
        raw_dict = _safe_instance_dict(obj, obj_t)
        slots_items = _safe_instance_slots(obj, obj_t)
        builtin_sub = _safe_builtin_subclass_payload(obj)
        if (
            _is_stdlib_module_name(cls_mod)
            and raw_dict is None
            and not slots_items
            and builtin_sub is None
        ):
            return {"__t__": "stdlib_opaque", "qual": qual}
        state_map: Dict[str, Any] = {}
        if type(raw_dict) is dict:
            rview = _safe_str_dict_view(raw_dict)
            if rview is None:
                raise ValueError("CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN")
            for k in sorted(rview.keys()):
                if k == "__weakref__":
                    continue
                state_map[k] = _canonicalize_callable_state(
                    rview[k],
                    active_ancestors=active_ancestors,
                    depth=depth + 1,
                    budget=rem_budget,
                    caller_names=caller_names,
                    dag_memo=memo,
                    cycle_deps=local_cycles,
                )
        for sname, s_val in slots_items:
            state_map[sname] = _canonicalize_callable_state(
                s_val,
                active_ancestors=active_ancestors,
                depth=depth + 1,
                budget=rem_budget,
                caller_names=caller_names,
                dag_memo=memo,
                cycle_deps=local_cycles,
            )
        encoded_sub = None
        if builtin_sub is not None:
            sub_kind, sub_items = builtin_sub
            encoded_sub = {
                "kind": sub_kind,
                "val": (
                    _canonicalize_dict_pairs(
                        sub_items,
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        caller_names=caller_names,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
                    if sub_kind == "dict"
                    else _canonicalize_callable_state(
                        sub_items,
                        active_ancestors=active_ancestors,
                        depth=depth + 1,
                        budget=rem_budget,
                        caller_names=caller_names,
                        dag_memo=memo,
                        cycle_deps=local_cycles,
                    )
                ),
            }
        return {
            "__t__": "object",
            "cls": qual,
            "type_def": _canonicalize_callable_state(
                obj_t,
                active_ancestors=active_ancestors,
                depth=depth + 1,
                budget=rem_budget,
                caller_names=caller_names,
                dag_memo=memo,
                cycle_deps=local_cycles,
            ),
            "state": state_map,
            "builtin_payload": encoded_sub,
        }

    active_ancestors.add(oid)
    try:
        result = _canonicalize_compound()
    finally:
        active_ancestors.discard(oid)

    escaped = local_cycles - {oid}
    if cycle_deps is not None and escaped:
        cycle_deps.update(escaped)
    if not is_stdlib_mod and not escaped:
        node_hash = sha256_digest(result)
        memo[memo_key] = (node_hash, obj)
        return {"__t__": "hashed_node", "sha256": node_hash}
    return result


def compute_callable_sha256(fn: Callable[..., Any]) -> str:
    """Compute deterministic `sha256:<64hex>` digest binding bytecode, closures, defaults, and globals."""
    basis = _canonicalize_callable_state(fn, active_ancestors=set(), depth=0, budget=[_MAX_CANONICAL_BUDGET])
    return sha256_digest(basis)


def _check_no_symlink_components(root_resolved: Path, target_rel: str) -> None:
    """Verify every existing segment from `root_resolved` down to `target_rel` is not a symlink."""
    assert_not_symlink(root_resolved)
    clean_rel = target_rel.replace("\\", "/").strip("/")
    if not clean_rel or clean_rel == ".":
        return
    cur = root_resolved
    for seg in clean_rel.split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            raise PermissionError("SECURITY_PATH_TRAVERSAL_REFUSED: '..' segment forbidden")
        cur = cur / seg
        assert_not_symlink(cur)


def _match_root_relative(raw_path: str, root: Path) -> Optional[str]:
    """Return relative sub-path if `raw_path` lexically starts under `root` or `root.resolve()`."""
    norm_raw = posixpath.normpath(raw_path.replace("\\", "/"))
    for base_str in (str(root).rstrip("/"), str(root.resolve()).rstrip("/")):
        if not base_str:
            continue
        if norm_raw == base_str:
            return "."
        if norm_raw.startswith(base_str + "/"):
            return norm_raw[len(base_str) + 1 :]
    return None


def _confine_path_under_roots(raw_path: str, roots: Sequence[Path]) -> Path:
    """Confine `raw_path` strictly under one of `roots` with symlink and traversal rejection."""
    cleaned = str(raw_path or "").strip()
    if not cleaned or "\x00" in cleaned:
        raise PermissionError("SECURITY_PATH_EMPTY_OR_NULL")
    if TROJAN_UNICODE_RE.search(cleaned):
        raise PermissionError("SECURITY_PATH_TROJAN_UNICODE")
    if cleaned == "~" or cleaned.startswith("~/") or _HOME_ENV_VAR_RE.search(cleaned):
        raise PermissionError(f"SECURITY_PATH_HOME_EXPANSION_FORBIDDEN: {redact_runtime_text(cleaned)}")
    lowered = cleaned.lower()
    if any(frag in lowered for frag in _SENSITIVE_PATH_FRAGMENTS):
        raise PermissionError("SECURITY_SENSITIVE_PATH_FORBIDDEN")
    if ".." in [seg for seg in cleaned.replace("\\", "/").split("/") if seg]:
        raise PermissionError("SECURITY_PATH_TRAVERSAL_REFUSED")

    is_abs = os.path.isabs(cleaned) or cleaned.startswith("/")
    for root in roots:
        root_resolved = root.resolve()
        rel = _match_root_relative(cleaned, root) if is_abs else cleaned
        if rel is None and is_abs:
            cand_path = Path(cleaned)
            assert_not_symlink(cand_path)
            try:
                rel_obj = cand_path.resolve().relative_to(root_resolved)
                rel = str(rel_obj) if str(rel_obj) != "." else "."
            except ValueError:
                rel = None
        if rel is None:
            continue
        _check_no_symlink_components(root_resolved, rel)
        safe = resolve_safe_child_path(root_resolved, rel)
        if safe is None:
            continue
        assert_not_symlink(safe)
        return safe
    raise PermissionError(f"SECURITY_PATH_OUTSIDE_CONFINEMENT: {redact_runtime_text(cleaned)}")


_MAX_STAGE_BYTES = 16 * 1024 * 1024


def _read_regular_file_nofollow(target_path: Path, *, capture_bytes: bool = False) -> Tuple[str, Tuple[int, int, int], Optional[bytes]]:
    """Open `target_path` with `O_RDONLY | O_NOFOLLOW`, verify regular file, and compute `sha256:<hex>`."""
    assert_not_symlink(target_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(target_path), flags)
    except OSError as exc:
        raise PermissionError(f"SECURITY_OPEN_FAILED_NOFOLLOW: {exc}") from exc
    chunks: List[bytes] = []
    total_read = 0
    keep_bytes = capture_bytes
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError("SECURITY_NON_REGULAR_FILE_FORBIDDEN")
        hasher = hashlib.sha256()
        for _ in range(100000):
            chunk = handle.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
            total_read += len(chunk)
            if keep_bytes:
                if total_read <= _MAX_STAGE_BYTES:
                    chunks.append(chunk)
                else:
                    keep_bytes = False
                    chunks.clear()
    captured = b"".join(chunks) if keep_bytes else None
    return f"sha256:{hasher.hexdigest()}", (int(st.st_dev), int(st.st_ino), int(st.st_size)), captured


def compute_file_sha256_confined(file_path: Path, allowed_roots: Sequence[Path]) -> Tuple[Path, str]:
    """Confine `file_path` under `allowed_roots`, open via `O_NOFOLLOW`, and return `(resolved, sha256:<hex>)`."""
    confined = _confine_path_under_roots(str(file_path), allowed_roots)
    digest, _, _ = _read_regular_file_nofollow(confined, capture_bytes=False)
    return confined, digest


def _compute_context_policy_hash_from_dict(ctx_dict: Dict[str, Any]) -> str:
    """Compute canonical `SecurityContext/1` policy digest strictly from an already-validated clean dict."""
    profile_raw = str(ctx_dict["profile"]).strip().upper()
    return sha256_digest(
        {
            "schema": ctx_dict["schema"],
            "profile": profile_raw,
            "workspace_root": ctx_dict["workspace_root"],
            "allowed_permissions": sorted(str(p) for p in ctx_dict["allowed_permissions"]),
            "network_allowed": bool(ctx_dict["network_allowed"]),
            "allow_untrusted_native": bool(ctx_dict["allow_untrusted_native"]),
        }
    )


def _compute_context_policy_hash(security_context: SecurityContext) -> str:
    """Recompute canonical `SecurityContext/1` policy digest via hook-free exact extraction."""
    try:
        clean_ctx_dict = extract_exact_security_context_dict(security_context)
    except (TypeError, ValueError) as exc:
        raise PermissionError(str(exc)) from exc
    return _compute_context_policy_hash_from_dict(clean_ctx_dict)


def _verify_context_policy_integrity(security_context: SecurityContext) -> str:
    """Fail closed if `security_context` is subclassed/tampered or `policy_hash` mismatches live fields."""
    try:
        clean_ctx_dict = extract_exact_security_context_dict(security_context)
    except (TypeError, ValueError) as exc:
        raise PermissionError(str(exc)) from exc
    expected_ctx_hash = _compute_context_policy_hash_from_dict(clean_ctx_dict)
    declared = clean_ctx_dict["policy_hash"].strip().lower()
    if not declared or not is_valid_sha256(declared):
        raise PermissionError("SECURITY_POLICY_HASH_MISSING_OR_INVALID")
    if not hmac.compare_digest(declared, expected_ctx_hash):
        raise PermissionError("SECURITY_POLICY_HASH_TAMPERED")
    return declared


def _compute_runner_policy_hash_from_dict(
    clean_ctx_dict: Dict[str, Any],
    scars: Sequence[GoldenScar],
) -> str:
    """Compute composite runner policy hash from an already-validated primitive context dict."""
    ctx_hash = _compute_context_policy_hash_from_dict(clean_ctx_dict)
    declared_raw = clean_ctx_dict.get("policy_hash")
    if type(declared_raw) is not str:
        raise PermissionError("SECURITY_POLICY_HASH_MISSING_OR_INVALID")
    declared = declared_raw.strip().lower()
    if not declared or not is_valid_sha256(declared):
        raise PermissionError("SECURITY_POLICY_HASH_MISSING_OR_INVALID")
    if not hmac.compare_digest(declared, ctx_hash):
        raise PermissionError("SECURITY_POLICY_HASH_TAMPERED")
    return sha256_digest(
        {
            "ctx_policy_hash": declared,
            "allowed_permissions": sorted(str(p) for p in clean_ctx_dict["allowed_permissions"]),
            "network_allowed": bool(clean_ctx_dict["network_allowed"]),
            "allow_untrusted_native": bool(clean_ctx_dict["allow_untrusted_native"]),
            "scars_count": len(scars),
            "scar_ids_digest": sha256_digest([s.id for s in scars]),
        }
    )


def _compute_runner_policy_hash(
    security_context: Union[SecurityContext, Dict[str, Any]],
    scars: Sequence[GoldenScar],
) -> str:
    """Compute composite runner policy hash binding verified context policy and scar ledger."""
    if type(security_context) is dict:
        try:
            clean_ctx_dict = sanitize_exact_json_value(security_context, allow_bytes=False)
        except (TypeError, ValueError) as exc:
            raise PermissionError(str(exc)) from exc
        if type(clean_ctx_dict) is not dict:
            raise PermissionError("UNTRUSTED_SECURITY_CONTEXT_STORAGE")
    else:
        try:
            clean_ctx_dict = extract_exact_security_context_dict(security_context)
        except (TypeError, ValueError) as exc:
            raise PermissionError(str(exc)) from exc
    return _compute_runner_policy_hash_from_dict(clean_ctx_dict, scars)


def _normalize_tool_spec_for_runner(tool_spec: Any) -> Dict[str, Any]:
    """Normalize an exact `ToolSpec` into an isolated built-in primitive dict without firing any hooks."""
    return extract_exact_tool_spec_dict(tool_spec)


def _normalize_security_context_for_runner(security_context: Any) -> Tuple[Dict[str, Any], str]:
    """Validate and copy an exact `SecurityContext` into plain primitives with zero constructor/hook calls."""
    try:
        clean_dict = extract_exact_security_context_dict(security_context)
        if clean_dict["schema"] != "SecurityContext/1":
            raise ValueError(f"INVALID_SCHEMA: expected SecurityContext/1, got '{clean_dict['schema']}'.")
        raw_root = validate_safe_text(clean_dict["workspace_root"], field_name="workspace_root")
        profile_str = clean_dict["profile"].strip().upper()
        if profile_str not in _VALID_SECURITY_PROFILES:
            raise ValueError(f"INVALID_SECURITY_PROFILE: {clean_dict['profile']!r}")
        cleaned_perms = sorted(
            validate_safe_text(perm, field_name="allowed_permissions")
            for perm in clean_dict["allowed_permissions"]
        )
    except (TypeError, ValueError) as exc:
        raise PermissionError(str(exc)) from exc

    normalized_dict: Dict[str, Any] = {
        "schema": "SecurityContext/1",
        "workspace_root": raw_root,
        "profile": profile_str,
        "allowed_permissions": cleaned_perms,
        "network_allowed": bool(clean_dict["network_allowed"]),
        "allow_untrusted_native": bool(clean_dict["allow_untrusted_native"]),
        "policy_hash": clean_dict["policy_hash"],
    }
    expected_ctx_hash = _compute_context_policy_hash_from_dict(normalized_dict)
    declared = normalized_dict["policy_hash"].strip().lower()
    if not declared or not is_valid_sha256(declared):
        raise PermissionError("SECURITY_POLICY_HASH_MISSING_OR_INVALID")
    if not hmac.compare_digest(declared, expected_ctx_hash):
        raise PermissionError("SECURITY_POLICY_HASH_TAMPERED")
    ws_raw = Path(raw_root)
    assert_not_symlink(ws_raw)
    ws_resolved = ws_raw.resolve()
    if not ws_resolved.is_dir():
        raise PermissionError("WORKSPACE_ROOT_NOT_A_DIRECTORY")
    normalized_dict["policy_hash"] = declared
    return normalized_dict, declared


def _is_path_under_dir(candidate: Path, base_dir: Path) -> bool:
    try:
        candidate.resolve().relative_to(base_dir.resolve())
        return True
    except ValueError:
        return False


def _decode_capped_utf8(raw: bytes, max_bytes: int) -> str:
    cap = max(0, int(max_bytes))
    if cap == 0 or not raw:
        return ""
    trimmed = raw[:cap]
    decoded = trimmed.decode("utf-8", errors="replace")
    encoded = decoded.encode("utf-8", errors="replace")
    if len(encoded) > cap:
        decoded = encoded[:cap].decode("utf-8", errors="ignore")
    return decoded


def _parse_json_output_if_applicable(stdout_s: str) -> Any:
    parsed_out: Any = stdout_s.strip()
    if parsed_out.startswith(("{", "[")):
        try:
            parsed_out = json.loads(parsed_out)
        except ValueError as _parse_err:
            _ = _parse_err
    return parsed_out


def _json_safe_output(obj: Any) -> Any:
    """Normalize runtime output values (e.g., Decimal, bytes, frozenset) for canonical JSON hashing & receipts."""
    if isinstance(obj, Enum):
        return obj.value
    if obj is None or isinstance(obj, (bool, int, str, Path)):
        return obj
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else repr(obj)
    if isinstance(obj, Decimal):
        return str(obj)
    if isinstance(obj, (bytes, bytearray)):
        return base64.b64encode(bytes(obj)).decode("ascii")
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return _json_safe_output(obj.to_dict())
    if isinstance(obj, dict):
        return {str(k): _json_safe_output(v) for k, v in obj.items()}
    if isinstance(obj, tuple):
        return tuple(_json_safe_output(v) for v in obj)
    if isinstance(obj, set):
        return {_json_safe_output(v) for v in obj}
    if isinstance(obj, frozenset):
        return sorted((_json_safe_output(v) for v in obj), key=lambda item: str(item))
    if isinstance(obj, list):
        return [_json_safe_output(v) for v in obj]
    return str(obj)


def _tagged_json_encode(obj: Any) -> Any:
    """Losslessly encode Python values (Decimal, bytes, tuple, set, Path, etc.) into JSON-safe primitives."""
    if obj is None or isinstance(obj, (bool, int, str)):
        return obj
    if isinstance(obj, float):
        if math.isfinite(obj):
            return obj
        return {"__kt__": "float", "v": repr(obj)}
    if isinstance(obj, Decimal):
        return {"__kt__": "decimal", "v": str(obj)}
    if isinstance(obj, bytes):
        return {"__kt__": "bytes", "v": base64.b64encode(obj).decode("ascii")}
    if isinstance(obj, bytearray):
        return {"__kt__": "bytearray", "v": base64.b64encode(bytes(obj)).decode("ascii")}
    if isinstance(obj, tuple):
        return {"__kt__": "tuple", "v": [_tagged_json_encode(item) for item in obj]}
    if isinstance(obj, set):
        return {"__kt__": "set", "v": [_tagged_json_encode(item) for item in obj]}
    if isinstance(obj, frozenset):
        return {"__kt__": "frozenset", "v": [_tagged_json_encode(item) for item in obj]}
    if isinstance(obj, Path):
        return {"__kt__": "path", "v": str(obj)}
    if isinstance(obj, list):
        return [_tagged_json_encode(item) for item in obj]
    if isinstance(obj, dict):
        if "__kt__" in obj or any(not isinstance(k, str) for k in obj):
            return {
                "__kt__": "dict",
                "v": [[_tagged_json_encode(k), _tagged_json_encode(v)] for k, v in obj.items()],
            }
        return {k: _tagged_json_encode(v) for k, v in obj.items()}
    return str(obj)


def _tagged_json_decode(node: Any) -> Any:
    """Restore Python values encoded with `_tagged_json_encode` without `pickle`."""
    if isinstance(node, list):
        return [_tagged_json_decode(item) for item in node]
    if isinstance(node, dict):
        if set(node.keys()) == {"__kt__", "v"}:
            tag = node["__kt__"]
            val = node["v"]
            if tag == "float":
                return float(val)
            if tag == "decimal":
                return Decimal(val)
            if tag == "bytes":
                return base64.b64decode(str(val).encode("ascii"))
            if tag == "bytearray":
                return bytearray(base64.b64decode(str(val).encode("ascii")))
            if tag == "tuple":
                return tuple(_tagged_json_decode(item) for item in val)
            if tag == "set":
                return set(_tagged_json_decode(item) for item in val)
            if tag == "frozenset":
                return frozenset(_tagged_json_decode(item) for item in val)
            if tag == "path":
                return Path(str(val))
            if tag == "dict":
                return {_tagged_json_decode(k): _tagged_json_decode(v) for k, v in val}
        return {k: _tagged_json_decode(v) for k, v in node.items()}
    return node


def _stage_verified_binary(
    confined_bin: Path,
    verified_bytes: bytes,
    expected_hex: str,
    ws_resolved: Optional[Path] = None,
) -> Tuple[Path, Path]:
    """Stage verified workspace executable bytes into a private 0o700 dir (`O_CREAT|O_EXCL|O_NOFOLLOW`, `0o500`)."""
    if ws_resolved is not None:
        assert_not_symlink(ws_resolved)
        kintsugi_dir = ws_resolved / ".kintsugi"
        assert_not_symlink(kintsugi_dir)
        kintsugi_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(kintsugi_dir, 0o700)
        assert_not_symlink(kintsugi_dir)
        raw_stage_dir = kintsugi_dir / f".stage_{secrets.token_hex(8)}"
        os.mkdir(raw_stage_dir, 0o700)
        os.chmod(raw_stage_dir, 0o700)
        assert_not_symlink(raw_stage_dir)
        stage_dir = raw_stage_dir.resolve()
    else:
        stage_dir = Path(tempfile.mkdtemp(prefix="kintsugi_stage_")).resolve()
        os.chmod(stage_dir, 0o700)
        assert_not_symlink(stage_dir)

    try:
        staged_path = stage_dir / confined_bin.name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(staged_path), flags, 0o500)
        with os.fdopen(fd, "wb") as handle:
            handle.write(verified_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(staged_path, 0o500)
        staged_digest, _, _ = _read_regular_file_nofollow(staged_path, capture_bytes=False)
        if not hmac.compare_digest(normalize_sha256_hex(staged_digest), expected_hex):
            raise PermissionError("TOCTOU_STAGED_BINARY_HASH_MISMATCH")
        return stage_dir, staged_path
    except Exception:
        shutil.rmtree(stage_dir, ignore_errors=True)
        raise


def _looks_like_path_value(value: str) -> bool:
    if not value:
        return False
    lowered = value.lower()
    if any(frag in lowered for frag in _SENSITIVE_PATH_FRAGMENTS):
        return True
    if value == "~" or value.startswith(("~/", "/", "./", "../", ".\\", "..\\")):
        return True
    if _HOME_ENV_VAR_RE.search(value):
        return True
    return ".." in [s for s in value.replace("\\", "/").split("/") if s]


def _validate_workspace_path_str(ws_root_str: str, target_path: Union[str, Path]) -> Path:
    """Verify `target_path` contains no symlinks and resolves inside `ws_root_str` without calling contract methods."""
    raw = str(target_path)
    if not raw or "\x00" in raw or TROJAN_UNICODE_RE.search(raw):
        raise PermissionError("SECURITY_INVALID_PATH: empty, NUL, or control characters in path.")
    ws_path = Path(ws_root_str)
    assert_not_symlink(ws_path)

    candidate_in = Path(raw)
    if candidate_in.is_absolute():
        assert_not_symlink(candidate_in)
        try:
            rel = candidate_in.relative_to(ws_path)
        except ValueError:
            resolved = candidate_in.resolve()
            try:
                rel = resolved.relative_to(ws_path.resolve())
            except ValueError as exc:
                raise PermissionError(
                    f"SECURITY_WORKSPACE_ESCAPE: '{target_path}' is outside workspace '{ws_root_str}'."
                ) from exc
        rel_str = str(rel) if str(rel) != "." else "."
    else:
        rel_str = raw

    if rel_str == ".":
        return ws_path.resolve()

    cur = ws_path
    for part in Path(rel_str).parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise PermissionError(f"SECURITY_PATH_TRAVERSAL: '..' segment rejected in '{target_path}'.")
        cur = cur / part
        assert_not_symlink(cur)

    resolved_child = resolve_safe_child_path(ws_path, rel_str)
    if resolved_child is None:
        raise PermissionError(
            f"SECURITY_WORKSPACE_ESCAPE: '{target_path}' escapes '{ws_root_str}'."
        )
    assert_not_symlink(resolved_child)
    return resolved_child


def _collect_and_confine_paths(
    obj: Any,
    security_context: Union[SecurityContext, Dict[str, Any]],
    ws_resolved: Path,
    *,
    key_hint: str = "",
) -> List[Path]:
    """Walk `obj` and verify every path-like argument stays strictly inside `workspace_root`."""
    if type(security_context) is dict:
        ws_root_raw = security_context.get("workspace_root")
        if type(ws_root_raw) is not str or not ws_root_raw:
            raise PermissionError("UNTRUSTED_SECURITY_CONTEXT_STORAGE")
        ws_root_str = ws_root_raw
    else:
        try:
            ws_root_str = extract_exact_security_context_dict(security_context)["workspace_root"]
        except (TypeError, ValueError) as exc:
            raise PermissionError(str(exc)) from exc
    raw_ws = Path(ws_root_str)

    def _walk(item: Any, hint: str) -> List[Path]:
        confined_paths: List[Path] = []
        if isinstance(item, Path):
            confined_paths.append(_validate_workspace_path_str(ws_root_str, item))
            return confined_paths
        if isinstance(item, str):
            key_is_path = any(part in hint.lower() for part in _PATH_ARG_KEY_HINTS)
            has_slash_rel = "/" in item or "\\" in item
            rel_symlink_probe = False
            if not _looks_like_path_value(item) and "\n" not in item and "\r" not in item and "\x00" not in item:
                candidate = ws_resolved / item
                try:
                    rel_symlink_probe = candidate.is_symlink() or (has_slash_rel and candidate.exists())
                except OSError:
                    rel_symlink_probe = True
            if key_is_path or _looks_like_path_value(item) or rel_symlink_probe:
                assert_not_symlink(raw_ws)
                confined = _confine_path_under_roots(item, (ws_resolved, raw_ws))
                _validate_workspace_path_str(ws_root_str, confined)
                confined_paths.append(confined)
            return confined_paths
        if isinstance(item, dict):
            for k, v in item.items():
                confined_paths.extend(_walk(v, str(k)))
        elif isinstance(item, (list, tuple)):
            for sub in item:
                confined_paths.extend(_walk(sub, hint))
        return confined_paths

    return _walk(obj, key_hint)


def _build_safe_env(workspace_resolved: Path) -> Dict[str, str]:
    """Construct a minimal, secret-free environment dictionary for confined child processes."""
    env: Dict[str, str] = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": str(workspace_resolved),
        "TMPDIR": str(workspace_resolved),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    for key in _SAFE_ENV_KEYS:
        if key in os.environ and key not in env:
            env[key] = os.environ[key]
    return env


def _build_receipt(
    *,
    run_id: str,
    status: ExecutionStatus,
    verification_status: str,
    exit_status: int,
    plan_hash: str,
    tool_hash: str,
    policy_hash: str,
    environment_hash: str,
    artifact_digests: Dict[str, str],
    resource_metrics: Dict[str, Any],
    stdout_excerpt: str = "",
    stderr_excerpt: str = "",
) -> ExecutionReceipt:
    """Create a canonical `ExecutionReceipt/1` with sealed `trace_digest` and `llm_calls=0`."""
    safe_stdout = redact_runtime_text(stdout_excerpt, max_len=4096)
    safe_stderr = redact_runtime_text(stderr_excerpt, max_len=4096)
    safe_metrics = redact_runtime_value(dict(resource_metrics))
    trace_digest = sha256_digest({
        "schema": "ExecutionReceipt/1",
        "run_id": run_id,
        "status": status.value,
        "verification_status": verification_status,
        "plan_hash": plan_hash,
        "tool_hash": tool_hash,
        "policy_hash": policy_hash,
        "environment_hash": environment_hash,
        "exit_status": exit_status,
        "artifact_digests": artifact_digests,
        "llm_calls": 0,
    })
    try:
        assert_execution_receipt_type_unmodified()
    except TypeError as exc:
        raise PermissionError(str(exc)) from exc
    return ExecutionReceipt(
        run_id=run_id,
        status=status,
        plan_hash=plan_hash,
        tool_hash=tool_hash,
        policy_hash=policy_hash,
        environment_hash=environment_hash,
        exit_status=exit_status,
        verification_status=verification_status,
        artifact_digests=dict(artifact_digests),
        resource_metrics=safe_metrics,
        trace_digest=trace_digest,
        llm_calls=0,
        stderr_excerpt=safe_stderr,
        stdout_excerpt=safe_stdout,
    )


def _invoke_oracle(
    oracle: Callable[..., Any],
    execution_result: Dict[str, Any],
    tool_spec: Any,
    args: Dict[str, Any],
    security_context: Union[SecurityContext, Dict[str, Any]],
) -> Tuple[bool, str]:
    """Run optional verification oracle safely; fail closed on exceptions or falsy output."""
    try:
        sig = inspect.signature(oracle)
        positional = [
            p
            for p in sig.parameters.values()
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in sig.parameters.values())
        if has_varargs or len(positional) >= 4:
            outcome = oracle(execution_result, tool_spec, args, security_context)
        elif len(positional) == 3:
            outcome = oracle(execution_result, tool_spec, args)
        elif len(positional) == 2:
            outcome = oracle(execution_result, args)
        elif len(positional) == 1:
            outcome = oracle(execution_result)
        else:
            outcome = oracle()
    except Exception as exc:
        return False, f"ORACLE_EXCEPTION: {redact_runtime_text(exc)}"

    if isinstance(outcome, bool):
        return outcome, "ORACLE_PASS" if outcome else "ORACLE_FAILED"
    if isinstance(outcome, tuple) and outcome:
        passed = bool(outcome[0])
        reason = str(outcome[1]) if len(outcome) > 1 else ("ORACLE_PASS" if passed else "ORACLE_FAILED")
        return passed, reason
    if isinstance(outcome, Mapping):
        if "passed" in outcome:
            passed = bool(outcome["passed"])
        elif "verified" in outcome:
            passed = bool(outcome["verified"])
        elif "ok" in outcome:
            passed = bool(outcome["ok"])
        else:
            passed = str(outcome.get("status", "")).upper() == "PASS"
        reason = str(outcome.get("reason") or ("ORACLE_PASS" if passed else "ORACLE_FAILED"))
        return passed, reason
    return False, "ORACLE_INVALID_RETURN"


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockRulesetAttrV4(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


_READONLY_SYSTEM_MMAP_PREFIXES: Tuple[str, ...] = (
    "/usr/lib/",
    "/lib/",
    "/lib64/",
    "/usr/share/",
)


def _revoke_inherited_shared_mmaps(ws_resolved: Optional[Path] = None) -> int:
    """Revoke ALL non-system `MAP_SHARED` memory mappings via `mprotect(PROT_NONE)` on Linux."""
    if not sys.platform.startswith("linux") or platform.system().lower() != "linux":
        return 0
    _ = ws_resolved
    maps_path = "/proc/self/maps"
    try:
        with open(maps_path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        raise PermissionError(f"SANDBOX_LINUX_MAPS_READ_FAILED:{exc}") from exc

    libc = ctypes.CDLL(None, use_errno=True)
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.mprotect.restype = ctypes.c_int

    revoked = 0
    for raw_line in lines:
        parts = raw_line.strip().split(None, 5)
        if len(parts) < 2:
            continue
        addr_range, perms = parts[0], parts[1]
        if len(perms) < 4 or perms[3] != "s":
            continue
        pathname = parts[5].strip() if len(parts) > 5 else ""
        if pathname.startswith("["):
            continue
        is_deleted = pathname.endswith(" (deleted)")
        is_writable = perms[1] == "w"
        if not is_writable and not is_deleted and pathname.startswith("/"):
            try:
                real_p = os.path.realpath(pathname)
                is_sys_path = (
                    real_p == "/etc/ld.so.cache" or real_p.startswith(_READONLY_SYSTEM_MMAP_PREFIXES)
                )
                if is_sys_path and os.lstat(real_p).st_uid == 0:
                    continue
            except OSError as exc:
                _ = exc
        start_hex, end_hex = addr_range.split("-", 1)
        start_addr = int(start_hex, 16)
        size = int(end_hex, 16) - start_addr
        if size <= 0:
            continue
        ctypes.set_errno(0)
        rc = int(libc.mprotect(ctypes.c_void_p(start_addr), ctypes.c_size_t(size), 0))
        if rc != 0:
            err_no = int(ctypes.get_errno())
            raise PermissionError(f"SANDBOX_LINUX_MMAP_REVOCATION_FAILED:rc={rc}:errno={err_no}")
        revoked += 1
    return revoked


def _sanitize_child_fds(write_fd: int, *, ws_resolved: Optional[Path] = None) -> int:
    """Sanitize stdio, close inherited FDs (except `write_fd`), and revoke external shared mmaps."""
    if write_fd <= 2:
        dup_cmd = getattr(fcntl, "F_DUPFD_CLOEXEC", fcntl.F_DUPFD)
        new_fd = fcntl.fcntl(write_fd, dup_cmd, 3)
        os.close(write_fd)
        write_fd = new_fd
    os.set_inheritable(write_fd, False)

    devnull_fd = os.open("/dev/null", os.O_RDWR)
    try:
        for target_fd in (0, 1, 2):
            if devnull_fd != target_fd:
                os.dup2(devnull_fd, target_fd)
    finally:
        if devnull_fd > 2:
            try:
                os.close(devnull_fd)
            except OSError as _dn_err:
                _ = _dn_err

    for fd_dir in ("/proc/self/fd", "/dev/fd"):
        if not os.path.isdir(fd_dir):
            continue
        try:
            open_fds = [int(name) for name in os.listdir(fd_dir) if name.isdigit()]
        except OSError as _ld_err:
            _ = _ld_err
            continue
        for fd in open_fds:
            if fd >= 3 and fd != write_fd:
                try:
                    os.close(fd)
                except OSError as _cf_err:
                    _ = _cf_err
        break

    try:
        soft_nofile, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError) as _rl_err:
        _ = _rl_err
        soft_nofile = 4096
    upper = min(max(int(soft_nofile), 4096), 65536)
    if write_fd > 3:
        os.closerange(3, write_fd)
    if upper > write_fd + 1:
        os.closerange(write_fd + 1, upper)

    _revoke_inherited_shared_mmaps(ws_resolved=ws_resolved)
    return write_fd


def _configure_linux_libc_syscalls(libc: ctypes.CDLL) -> None:
    """Configure 64-bit safe ctypes prototypes on Linux libc `prctl` and `syscall`."""
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    libc.syscall.argtypes = [ctypes.c_long, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.syscall.restype = ctypes.c_long


def probe_linux_landlock_available() -> Tuple[bool, int]:
    """Return `(available, errno)` by probing `landlock_create_ruleset(NULL, 0, VERSION)` on Linux."""
    if not sys.platform.startswith("linux"):
        return False, 0
    if platform.machine().lower() not in {"x86_64", "amd64", "aarch64", "arm64"}:
        return False, 0
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        _configure_linux_libc_syscalls(libc)
        ctypes.set_errno(0)
        abi_ver = int(libc.syscall(444, 0, 0, 1, 0, 0))
        if abi_ver >= 1:
            return True, 0
        return False, int(ctypes.get_errno())
    except (OSError, AttributeError) as exc:
        return False, int(getattr(exc, "errno", 0) or 0)


def _apply_macos_seatbelt_in_child(ws_resolved: Path) -> None:
    """Enforce real macOS Seatbelt confinement on the current forked child process (fail closed)."""
    profile = build_seatbelt_profile(ws_resolved)
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    lib.sandbox_init.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char_p)]
    lib.sandbox_init.restype = ctypes.c_int
    err_ptr = ctypes.c_char_p()
    rc = lib.sandbox_init(profile.encode("utf-8"), 0, ctypes.byref(err_ptr))
    if rc != 0:
        detail = err_ptr.value.decode("utf-8", errors="replace") if err_ptr.value else f"rc={rc}"
        raise PermissionError(f"SEATBELT_CHILD_INIT_FAILED:{detail}")


def _apply_linux_landlock_in_child(ws_resolved: Path, *, network_allowed: bool = False) -> bool:
    """Apply Linux Landlock LSM confinement inside forked child when supported by kernel."""
    machine = platform.machine().lower()
    if machine not in {"x86_64", "amd64", "aarch64", "arm64"}:
        return False
    # Linux ABI syscalls are 444/445/446 on both x86_64 and aarch64.
    nr_create_ruleset = 444
    nr_add_rule = 445
    nr_restrict_self = 446
    pr_set_no_new_privs = 38
    landlock_rule_path_beneath = 1
    landlock_create_ruleset_version = 1
    fs_read_exec = 0x1 | 0x4 | 0x8  # EXECUTE | READ_FILE | READ_DIR
    fs_rw_all = 0x1FFF  # full ABI v1 FS rights inside workspace
    net_bind_connect = 0x1 | 0x2  # LANDLOCK_ACCESS_NET_BIND_TCP | CONNECT_TCP

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        _configure_linux_libc_syscalls(libc)
        if libc.prctl(pr_set_no_new_privs, 1, 0, 0, 0) != 0:
            return False
        abi_ver = int(libc.syscall(nr_create_ruleset, 0, 0, landlock_create_ruleset_version, 0, 0))
        ruleset_fd = -1
        if (not network_allowed) and abi_ver >= 4:
            attr_v4 = _LandlockRulesetAttrV4(handled_access_fs=fs_rw_all, handled_access_net=net_bind_connect)
            ruleset_fd = int(
                libc.syscall(nr_create_ruleset, ctypes.addressof(attr_v4), ctypes.sizeof(attr_v4), 0, 0, 0)
            )
        if ruleset_fd < 0:
            attr_v1 = _LandlockRulesetAttr(handled_access_fs=fs_rw_all)
            ruleset_fd = int(
                libc.syscall(nr_create_ruleset, ctypes.addressof(attr_v1), ctypes.sizeof(attr_v1), 0, 0, 0)
            )
        if ruleset_fd < 0:
            return False
    except OSError:
        return False

    try:
        o_path = getattr(os, "O_PATH", os.O_RDONLY)

        def _allow_tree(path_obj: Path, access_mask: int) -> bool:
            if not path_obj.exists():
                return True
            try:
                pfd = os.open(str(path_obj), o_path)
            except OSError:
                return False
            try:
                rule = _LandlockPathBeneathAttr(allowed_access=access_mask, parent_fd=pfd)
                rc = int(libc.syscall(nr_add_rule, ruleset_fd, landlock_rule_path_beneath, ctypes.addressof(rule), 0, 0))
                return rc == 0
            finally:
                os.close(pfd)

        if not _allow_tree(ws_resolved, fs_rw_all):
            return False
        ro_roots = [
            Path("/usr"),
            Path("/lib"),
            Path("/lib64"),
            Path("/bin"),
            Path("/sbin"),
            Path("/etc"),
            Path("/dev"),
            Path("/proc"),
            Path("/sys"),
            Path(sys.prefix).resolve(),
            Path(sys.base_prefix).resolve(),
        ]
        seen_ro: Set[str] = set()
        for root_p in ro_roots:
            key = str(root_p)
            if key in seen_ro or not root_p.exists():
                continue
            seen_ro.add(key)
            if not _allow_tree(root_p, fs_read_exec):
                return False

        return int(libc.syscall(nr_restrict_self, ruleset_fd, 0, 0, 0, 0)) == 0
    except OSError:
        return False
    finally:
        try:
            os.close(ruleset_fd)
        except OSError as _close_err:
            _ = _close_err


def _apply_linux_seccomp_network_deny_in_child(*, allow_exec: bool) -> bool:
    """Install kernel seccomp-BPF filter blocking network (and non-permitted exec) syscalls on Linux."""
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        expected_arch = 0xC000003E  # AUDIT_ARCH_X86_64
        sys_seccomp = 317
        denied_nrs: List[int] = [41, 42, 43, 44, 45, 46, 47, 49, 50, 53, 288, 299, 307, 425]
        if not allow_exec:
            denied_nrs.extend([59, 322])  # execve, execveat
    elif machine in {"aarch64", "arm64"}:
        expected_arch = 0xC00000B7  # AUDIT_ARCH_AARCH64
        sys_seccomp = 277
        denied_nrs = [198, 199, 200, 201, 202, 203, 206, 207, 211, 212, 242, 243, 269, 425]
        if not allow_exec:
            denied_nrs.extend([221, 281])  # execve, execveat
    else:
        return False

    bpf_ld_w_abs = 0x20
    bpf_jmp_jeq_k = 0x15
    bpf_ret_k = 0x06
    seccomp_ret_allow = 0x7FFF0000
    seccomp_ret_errno_eperm = 0x00050001  # SECCOMP_RET_ERRNO | 1 (Linux EPERM)
    pr_set_seccomp = 22
    seccomp_mode_filter = 2
    pr_set_no_new_privs = 38
    seccomp_set_mode_filter = 1

    n = len(denied_nrs)
    insns: List[bytes] = [
        struct.pack("=HBBI", bpf_ld_w_abs, 0, 0, 4),  # load seccomp_data.arch
        struct.pack("=HBBI", bpf_jmp_jeq_k, 0, n + 2, expected_arch),  # mismatch -> RET EPERM
        struct.pack("=HBBI", bpf_ld_w_abs, 0, 0, 0),  # load seccomp_data.nr
    ]
    for j, nr in enumerate(denied_nrs):
        insns.append(struct.pack("=HBBI", bpf_jmp_jeq_k, n - j, 0, nr))
    insns.append(struct.pack("=HBBI", bpf_ret_k, 0, 0, seccomp_ret_allow))
    insns.append(struct.pack("=HBBI", bpf_ret_k, 0, 0, seccomp_ret_errno_eperm))

    raw_bpf = b"".join(insns)
    bpf_buf = ctypes.create_string_buffer(raw_bpf, len(raw_bpf))
    fprog = _SockFprog(len=len(insns), filter=ctypes.addressof(bpf_buf))

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        _configure_linux_libc_syscalls(libc)
        if libc.prctl(pr_set_no_new_privs, 1, 0, 0, 0) != 0:
            return False
        if libc.prctl(pr_set_seccomp, seccomp_mode_filter, ctypes.addressof(fprog), 0, 0) == 0:
            return True
        return int(libc.syscall(sys_seccomp, seccomp_set_mode_filter, 0, ctypes.addressof(fprog), 0, 0)) == 0
    except OSError:
        return False


def _apply_linux_netns_isolation_in_child() -> bool:
    """Secondary kernel network isolation fallback via CLONE_NEWUSER | CLONE_NEWNET."""
    clone_newuser = 0x10000000
    clone_newnet = 0x40000000
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        unshare_fn = getattr(libc, "unshare", None)
        if unshare_fn is None:
            return False
        unshare_fn.argtypes = [ctypes.c_int]
        unshare_fn.restype = ctypes.c_int
        return int(unshare_fn(clone_newuser | clone_newnet)) == 0
    except OSError:
        return False


def _install_child_audit_hook(
    ws_resolved: Path,
    *,
    network_allowed: bool,
    allowed_permissions: FrozenSet[str],
    kernel_sandbox_active: bool,
) -> None:
    """Install irremovable CPython audit hook inside isolated child enforcing workspace, ctypes, and net bounds."""
    allow_exec = bool(allowed_permissions & _AUDIT_EXEC_PERMISSIONS)

    def _confine_hook_path(raw_path: Any, *, allow_dev_null: bool = False) -> Path:
        if raw_path is None:
            raise PermissionError("SANDBOX_EMPTY_PATH_FORBIDDEN")
        raw_str = os.fsdecode(os.fspath(raw_path))
        if not raw_str or "\x00" in raw_str or TROJAN_UNICODE_RE.search(raw_str):
            raise PermissionError("SANDBOX_INVALID_PATH_FORBIDDEN")
        if allow_dev_null and raw_str == "/dev/null":
            return Path("/dev/null")
        try:
            cand = Path(raw_str)
            resolved = cand.resolve()
            rel = resolved.relative_to(ws_resolved)
        except (OSError, ValueError) as exc:
            raise PermissionError(f"SANDBOX_OUTSIDE_WORKSPACE_FORBIDDEN:{raw_str}") from exc
        cur = ws_resolved
        for part in rel.parts:
            if part in ("", "."):
                continue
            cur = cur / part
            assert_not_symlink(cur)
        return resolved

    def _reject_rel_dir_fd(path_arg: Any, dir_fd: Any) -> None:
        if dir_fd is not None:
            raw_str = os.fsdecode(os.fspath(path_arg)) if isinstance(path_arg, (str, bytes, os.PathLike)) else ""
            if not os.path.isabs(raw_str):
                raise PermissionError("SANDBOX_DIR_FD_ESCAPE_FORBIDDEN")

    def _hook(event: str, args: Tuple[Any, ...]) -> None:
        if event in {"ctypes.dlopen", "ctypes.dlsym"}:
            raise PermissionError("SANDBOX_CTYPES_FORBIDDEN")

        if event in {"socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg", "urllib.Request", "http.client.connect"}:
            if not network_allowed:
                raise PermissionError(f"SANDBOX_NETWORK_FORBIDDEN:{event}")
            return

        if event in {"subprocess.Popen", "os.posix_spawn", "os.posix_spawnp", "os.system", "os.exec"}:
            if not allow_exec:
                raise PermissionError(f"SANDBOX_EXEC_PERMISSION_REQUIRED:{event}")
            if event in {"os.system", "os.exec"} and not kernel_sandbox_active:
                raise PermissionError(f"SANDBOX_UNSANDBOXED_EXEC_FORBIDDEN:{event}")
            return

        if event == "open":
            if not args:
                return
            path_or_fd = args[0]
            if isinstance(path_or_fd, int):
                return
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 else -1
            mutating = (
                (isinstance(mode, str) and any(ch in mode for ch in ("w", "a", "x", "+")))
                or (
                    isinstance(flags, int)
                    and flags >= 0
                    and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
                )
            )
            if mutating:
                _confine_hook_path(path_or_fd, allow_dev_null=True)
            else:
                raw_low = os.fsdecode(os.fspath(path_or_fd)).lower()
                if any(frag in raw_low for frag in _SENSITIVE_PATH_FRAGMENTS):
                    _confine_hook_path(path_or_fd)
            return

        if event == "os.chdir":
            if args:
                _confine_hook_path(args[0])
            return

        if event in {"os.remove", "os.unlink", "os.rmdir"}:
            if args:
                _reject_rel_dir_fd(args[0], args[1] if len(args) > 1 else None)
                _confine_hook_path(args[0])
            return

        if event in {"os.mkdir", "os.chmod"}:
            if args:
                _reject_rel_dir_fd(args[0], args[2] if len(args) > 2 else None)
                _confine_hook_path(args[0])
            return

        if event == "os.chown":
            if args:
                _reject_rel_dir_fd(args[0], args[3] if len(args) > 3 else None)
                _confine_hook_path(args[0])
            return

        if event in {"os.truncate", "os.utime", "os.chflags", "shutil.rmtree"}:
            if args:
                _confine_hook_path(args[0])
            return

        if event in {"os.rename", "os.replace", "os.link"}:
            if len(args) >= 2:
                _reject_rel_dir_fd(args[0], args[2] if len(args) > 2 else None)
                _reject_rel_dir_fd(args[1], args[3] if len(args) > 3 else None)
                _confine_hook_path(args[0])
                _confine_hook_path(args[1])
            return

        if event == "os.symlink":
            if len(args) >= 2:
                _reject_rel_dir_fd(args[1], args[2] if len(args) > 2 else None)
                link_dst = _confine_hook_path(args[1])
                raw_src = os.fsdecode(os.fspath(args[0]))
                target_cand = Path(raw_src) if os.path.isabs(raw_src) else (link_dst.parent / raw_src)
                _confine_hook_path(target_cand)
            return

        if event in {"shutil.move", "shutil.copyfile", "shutil.copymode", "shutil.chown"}:
            if args:
                _confine_hook_path(args[0])
            if len(args) >= 2 and isinstance(args[1], (str, bytes, os.PathLike)):
                _confine_hook_path(args[1])
            return

    sys.addaudithook(_hook)


class SecureRunner:
    """Zero-trust runtime adapter re-verifying every policy and integrity invariant per run."""

    def __init__(
        self,
        *,
        allowed_callables: Optional[Mapping[str, Callable[..., Any]]] = None,
        trusted_tool_roots: Sequence[Path | str] = (),
        default_timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        scars: Optional[Sequence[GoldenScar]] = None,
        scars_path: Optional[Path | str] = None,
        config: Optional[KintsugiConfig] = None,
        sandbox: Optional[ToolSandbox] = None,
        require_os_sandbox: bool = True,
        allow_in_process_callable: bool = False,
        allow_trusted_host_callables: bool = False,
        attestation_authority: Optional[AttestationAuthority] = None,
    ) -> None:
        if attestation_authority is not None and not isinstance(attestation_authority, AttestationAuthority):
            raise ValueError("INVALID_ATTESTATION_AUTHORITY: expected AttestationAuthority instance.")
        self._allowed_callables: Dict[str, Callable[..., Any]] = dict(allowed_callables or {})
        self._trusted_host_callable_ids: set[str] = set()
        self._trusted_host_callable_bindings: Dict[str, Dict[str, Any]] = {}
        self._trusted_host_adapters: Dict[str, Tuple[Callable[..., Any], str]] = {}
        self._attestation_authority: Optional[AttestationAuthority] = attestation_authority
        self._allow_trusted_host_callables = bool(allow_trusted_host_callables)
        self._trusted_tool_roots: Tuple[Path, ...] = tuple(Path(r) for r in trusted_tool_roots)
        self._config = config
        cfg_timeout = (
            float(config.github_public.max_runtime_seconds)
            if config is not None and str(config.profile.value) == "GITHUB_PUBLIC"
            else float(default_timeout_seconds)
        )
        self._default_timeout_seconds = max(0.05, min(float(default_timeout_seconds), cfg_timeout))
        self._max_output_bytes = max(1024, int(max_output_bytes))
        self._override_scars: Optional[List[GoldenScar]] = list(scars) if scars is not None else None
        self._scars_path: Optional[Path] = Path(scars_path) if scars_path is not None else None
        self._explicit_sandbox: Optional[ToolSandbox] = sandbox
        self._require_os_sandbox: bool = bool(require_os_sandbox)
        self._allow_in_process_callable: bool = bool(allow_in_process_callable)
        self._sandboxes: Dict[Path, ToolSandbox] = {}

    def _get_sandbox(self, ws_resolved: Path) -> ToolSandbox:
        if self._explicit_sandbox is not None:
            sb_root = getattr(self._explicit_sandbox, "workspace_root", None)
            if (
                sb_root is None
                or Path(sb_root).resolve() == ws_resolved
                or getattr(self._explicit_sandbox, "_force_unavailable", False)
            ):
                return self._explicit_sandbox
            probe = self._explicit_sandbox.probe_isolation()
            if not probe.all_passed:
                return self._explicit_sandbox
            raise PermissionError("SANDBOX_WORKSPACE_MISMATCH")

        cached = self._sandboxes.get(ws_resolved)
        if cached is None:
            cached = ToolSandbox(
                ws_resolved,
                default_timeout_s=self._default_timeout_seconds,
                max_output_bytes=self._max_output_bytes,
            )
            self._sandboxes[ws_resolved] = cached
        return cached

    @staticmethod
    def _is_sandbox_mandatory(tool_spec: Dict[str, Any]) -> bool:
        source_low = tool_spec["source"].strip().lower()
        return source_low in {"forge_native", "forged"} or bool(tool_spec["runtime_requirements"].get("sandbox_required"))

    def register_callable(self, name: str, fn: Callable[..., Any]) -> str:
        """Explicitly allowlist a local Python callable and return its `sha256:<64hex>` digest."""
        if type(name) is not str or not name or not _SAFE_TOOL_ID_RE.fullmatch(name):
            raise ValueError(f"Invalid callable name: {name!r}")
        if not callable(fn):
            raise TypeError(f"Callable expected for {name!r}")
        self._allowed_callables[name] = fn
        self._trusted_host_callable_ids.discard(name)
        self._trusted_host_callable_bindings.pop(name, None)
        return compute_callable_sha256(fn)

    def register_trusted_host_callable(
        self,
        name: str,
        fn: Callable[..., Any],
        *,
        required_permissions: Optional[Sequence[str]] = None,
        bound_spec_digest: Optional[str] = None,
    ) -> str:
        """Privileged opt-in for *host-owned* Python functions with optional immutable contract binding.

        This API intentionally does not enable execution by itself. The runner
        must separately allow trusted host callables, verify cryptographic
        attestation via `attestation_authority`, and match immutable permissions.
        """
        digest = self.register_callable(name, fn)
        norm_perms: Optional[FrozenSet[str]] = None
        if required_permissions is not None:
            perm_vals: List[str] = []
            for p in required_permissions:
                if type(p) is not str:
                    raise TypeError("INVALID_REQUIRED_PERMISSION_TYPE")
                stripped = p.strip().lower()
                if stripped:
                    perm_vals.append(stripped)
            norm_perms = frozenset(perm_vals)
        if bound_spec_digest is not None and type(bound_spec_digest) is not str:
            raise TypeError("INVALID_BOUND_SPEC_DIGEST_TYPE")
        norm_bound_digest = (
            normalize_sha256(bound_spec_digest, field_name="bound_spec_digest")
            if bound_spec_digest is not None
            else None
        )
        self._trusted_host_callable_ids.add(name)
        self._trusted_host_callable_bindings[name] = {
            "fn": fn,
            "callable_hash": digest,
            "required_permissions": norm_perms,
            "bound_spec_digest": norm_bound_digest,
        }
        return digest

    def bind_trusted_host_callable_spec(self, name: str, bound_spec_digest: str) -> None:
        """Bind a registered trusted-host callable to an immutable `ToolSpec` security digest."""
        if type(name) is not str:
            raise TypeError("INVALID_TRUSTED_HOST_CALLABLE_NAME_TYPE")
        if type(bound_spec_digest) is not str:
            raise TypeError("INVALID_BOUND_SPEC_DIGEST_TYPE")
        binding = self._trusted_host_callable_bindings.get(name)
        if binding is None:
            raise KeyError(f"UNKNOWN_TRUSTED_HOST_CALLABLE:{name}")
        norm_digest = normalize_sha256(bound_spec_digest, field_name="bound_spec_digest")
        existing = binding.get("bound_spec_digest")
        if existing is not None and not hmac.compare_digest(existing, norm_digest):
            raise PermissionError(f"TRUSTED_HOST_CALLABLE_SPEC_ALREADY_BOUND:{name}")
        binding["bound_spec_digest"] = norm_digest

    def register_trusted_host_adapter(self, adapter_id: str, fn: Callable[..., Any]) -> str:
        """Explicit privileged registration for host-owned adapter callables (isolated child execution)."""
        if type(adapter_id) is not str or not adapter_id or not _SAFE_TOOL_ID_RE.fullmatch(adapter_id):
            raise ValueError(f"Invalid adapter callable id: {adapter_id!r}")
        if not callable(fn):
            raise TypeError(f"Callable expected for adapter {adapter_id!r}")
        digest = compute_callable_sha256(fn)
        self._trusted_host_adapters[adapter_id] = (fn, digest)
        return digest

    def has_trusted_host_adapter(
        self, adapter_id: str, expected_callable: Optional[Callable[..., Any]] = None
    ) -> bool:
        """Return True if `adapter_id` is registered as a trusted host adapter matching optional callable."""
        if type(adapter_id) is not str:
            return False
        entry = self._trusted_host_adapters.get(adapter_id)
        if entry is None:
            return False
        reg_fn, reg_digest = entry
        if expected_callable is not None and reg_fn is not expected_callable:
            return False
        try:
            live_digest = compute_callable_sha256(reg_fn)
        except ValueError:
            return False
        return hmac.compare_digest(live_digest, reg_digest)

    def execute_trusted_host_adapter(
        self,
        adapter_spec: Any,
        payload: Any,
        *,
        security_context: SecurityContext,
        expected_callable: Optional[Callable[..., Any]] = None,
        timeout_seconds: Optional[float] = None,
    ) -> Any:
        """Execute a cryptographically attested trusted-host adapter callable inside child isolation."""
        if not self._allow_trusted_host_callables:
            raise PermissionError("TRUSTED_HOST_ADAPTER_EXECUTION_DISABLED")
        if self._attestation_authority is None or not self._attestation_authority.has_registered_verifiers:
            raise PermissionError("MISSING_ATTESTATION_AUTHORITY")
        if timeout_seconds is not None and type(timeout_seconds) is not int and type(timeout_seconds) is not float:
            raise PermissionError("INVALID_ADAPTER_TIMEOUT_TYPE")
        clean_ctx, _ = _normalize_security_context_for_runner(security_context)
        try:
            clean_adapter = extract_exact_adapter_spec_dict(adapter_spec)
            safe_payload = sanitize_exact_json_value(payload, allow_bytes=True)
        except (TypeError, ValueError) as exc:
            raise PermissionError(str(exc)) from exc

        adapter_id = clean_adapter["adapter_id"]
        adapter_hash = clean_adapter["adapter_hash"]
        corpus_hash = clean_adapter["verification_corpus_hash"]
        entry = self._trusted_host_adapters.get(adapter_id)
        if entry is None:
            raise PermissionError(f"UNREGISTERED_TRUSTED_HOST_ADAPTER:{adapter_id}")
        reg_fn, reg_digest = entry
        if expected_callable is not None and reg_fn is not expected_callable:
            raise PermissionError(f"ADAPTER_CALLABLE_IDENTITY_MISMATCH:{adapter_id}")
        hygiene_err = validate_trusted_host_callable_hygiene(reg_fn)
        if hygiene_err:
            raise PermissionError(hygiene_err)
        try:
            live_digest = compute_callable_sha256(reg_fn)
        except ValueError as exc:
            raise PermissionError(str(exc)) from exc
        if not hmac.compare_digest(live_digest, reg_digest):
            raise PermissionError(f"TOCTOU_ADAPTER_CALLABLE_HASH_CHANGED:{adapter_id}")
        att = clean_adapter.get("verification_attestation") or {}
        if not self._attestation_authority.verify_adapter_attestation(
            att,
            expected_adapter_id=adapter_id,
            expected_adapter_hash=adapter_hash,
            expected_corpus_hash=corpus_hash,
            expected_callable_hash=live_digest,
        ):
            raise PermissionError(f"UNTRUSTED_OR_INVALID_ADAPTER_ATTESTATION:{adapter_id}")

        ws_resolved = Path(clean_ctx["workspace_root"]).resolve()
        ctx_max_timeout = self._default_timeout_seconds
        req_timeout = timeout_seconds if timeout_seconds is not None else self._default_timeout_seconds
        effective_timeout = max(0.01, min(float(req_timeout), ctx_max_timeout))
        max_out_bytes = self._max_output_bytes

        adapter_ctx: Dict[str, Any] = {
            "schema": "SecurityContext/1",
            "workspace_root": str(ws_resolved),
            "profile": clean_ctx["profile"],
            "allowed_permissions": ["fs.read", "fs.write"],
            "network_allowed": False,
            "allow_untrusted_native": False,
        }

        def _adapter_invoke(box: Dict[str, Any]) -> Any:
            return reg_fn(box["payload"])

        if hasattr(os, "fork"):
            exit_code, raw_output, _stdout_raw, stderr_raw, timed_out = self._execute_callable_forked(
                _adapter_invoke,
                {"payload": safe_payload},
                ws_resolved,
                effective_timeout,
                max_out_bytes,
                security_context=adapter_ctx,
            )
        else:
            exit_code, raw_output, _stdout_raw, stderr_raw, timed_out = self._execute_callable_in_process(
                _adapter_invoke, {"payload": safe_payload}, ws_resolved, effective_timeout
            )
        if timed_out or exit_code != 0:
            raise RuntimeError(f"ADAPTER_EXEC_FAILED:{adapter_id}:{stderr_raw or f'exit={exit_code}'}")
        return raw_output

    def _load_scars(
        self, ws_resolved: Path, security_context: Union[SecurityContext, Dict[str, Any]]
    ) -> List[GoldenScar]:
        if self._override_scars is not None:
            return list(self._override_scars)
        scars_path = self._scars_path or (ws_resolved / ".kintsugi" / "scars.json")
        if scars_path.is_symlink() or (scars_path.parent.exists() and scars_path.parent.is_symlink()):
            raise PermissionError("SECURITY_SYMLINK_REFUSED: .kintsugi/scars.json path is a symlink")
        ledger = ScarLedger(scars_path, ensure_builtin_crs=True)
        ledger.ensure_builtin_crs_rules(persist=False)
        return ledger.all()

    def _verify_trust_and_identity_normalized(
        self, clean_spec: Optional[Dict[str, Any]]
    ) -> Tuple[Optional[ExecutionStatus], str, str]:
        if clean_spec is None:
            return ExecutionStatus.NO_VERIFIED_TOOL, "", "TOOL_NOT_FOUND"
        tool_id = clean_spec["tool_id"]
        if not tool_id or not _SAFE_TOOL_ID_RE.fullmatch(tool_id):
            return ExecutionStatus.PERMISSION_DENIED, tool_id, "INVALID_TOOL_ID"
        if TROJAN_UNICODE_RE.search(tool_id) or PROMPT_INJECTION_RE.search(tool_id):
            return ExecutionStatus.PERMISSION_DENIED, tool_id, "UNSAFE_TOOL_ID_CONTENT"
        status_str = clean_spec["trust_status"].strip().upper()
        if status_str == "DISCOVERED":
            return ExecutionStatus.NO_VERIFIED_TOOL, tool_id, "TOOL_TRUST_STATUS_DISCOVERED"
        if status_str != "VERIFIED":
            return ExecutionStatus.PERMISSION_DENIED, tool_id, f"TOOL_TRUST_STATUS_{status_str or 'UNKNOWN'}"
        bin_hash = clean_spec["binary_hash"]
        ver_att = clean_spec.get("verification_attestation")
        if not has_valid_verification_attestation(ver_att, bin_hash, tool_id):
            return ExecutionStatus.PERMISSION_DENIED, tool_id, "MISSING_OR_INVALID_VERIFICATION_ATTESTATION"
        if self._attestation_authority is None or not self._attestation_authority.has_registered_verifiers:
            return ExecutionStatus.PERMISSION_DENIED, tool_id, "MISSING_ATTESTATION_AUTHORITY"
        try:
            expected_spec_digest = compute_tool_spec_security_digest(clean_spec)
        except (TypeError, ValueError):
            return ExecutionStatus.PERMISSION_DENIED, tool_id, "INVALID_TOOL_SPEC_SECURITY_DIGEST"
        if not self._attestation_authority.verify_attestation(
            ver_att if ver_att is not None else {},
            expected_tool_id=tool_id,
            expected_binary_hash=bin_hash,
            expected_spec_digest=expected_spec_digest,
        ):
            return ExecutionStatus.PERMISSION_DENIED, tool_id, "UNTRUSTED_OR_INVALID_ATTESTATION_SIGNATURE"
        runtime_reqs = clean_spec["runtime_requirements"]
        raw_callable_name = runtime_reqs.get("callable_name")
        if raw_callable_name is not None and type(raw_callable_name) is not str:
            return ExecutionStatus.PERMISSION_DENIED, tool_id, "INVALID_CALLABLE_NAME_TYPE"
        callable_key = raw_callable_name.strip() if (raw_callable_name is not None and raw_callable_name.strip()) else tool_id
        binding = self._trusted_host_callable_bindings.get(callable_key)
        if binding is not None:
            bound_digest = binding.get("bound_spec_digest")
            if bound_digest is not None and not hmac.compare_digest(expected_spec_digest, bound_digest):
                return ExecutionStatus.PERMISSION_DENIED, tool_id, "TRUSTED_HOST_CALLABLE_SPEC_DIGEST_MISMATCH"
        entrypoint_raw = clean_spec.get("entrypoint")
        callable_fn = binding.get("fn") if binding is not None else None
        if callable_fn is None:
            callable_fn = self._allowed_callables.get(callable_key)
        if callable_fn is not None and not entrypoint_raw:
            hygiene_err = validate_trusted_host_callable_hygiene(callable_fn)
            if hygiene_err:
                return ExecutionStatus.PERMISSION_DENIED, tool_id, hygiene_err
        return None, tool_id, ""

    def _verify_trust_and_identity(self, tool_spec: Any) -> Tuple[Optional[ExecutionStatus], str, str]:
        if tool_spec is None:
            return ExecutionStatus.NO_VERIFIED_TOOL, "", "TOOL_NOT_FOUND"
        try:
            clean_spec = _normalize_tool_spec_for_runner(tool_spec)
        except (TypeError, ValueError, PermissionError) as exc:
            return ExecutionStatus.PERMISSION_DENIED, "", str(exc)
        return self._verify_trust_and_identity_normalized(clean_spec)

    def _verify_binary_and_callable_snapshot(
        self,
        tool_spec: Dict[str, Any],
        tool_id: str,
        ws_resolved: Path,
        security_context: Union[SecurityContext, Dict[str, Any]],
    ) -> Tuple[Optional[Path], Optional[Callable[..., Any]], str, Optional[Tuple[int, int, int]], Optional[bytes], str]:
        expected_hex = normalize_sha256_hex(tool_spec["binary_hash"])
        if not expected_hex:
            raise PermissionError("MISSING_OR_INVALID_TOOL_SHA256")

        trusted_roots: List[Path] = [ws_resolved]
        for raw_root in self._trusted_tool_roots:
            root_path = Path(raw_root)
            assert_not_symlink(root_path)
            trusted_roots.append(root_path.resolve())

        entrypoint_raw = tool_spec.get("entrypoint")
        raw_cname = tool_spec["runtime_requirements"].get("callable_name")
        callable_key = raw_cname.strip() if (type(raw_cname) is str and raw_cname.strip()) else tool_id
        callable_fn = self._allowed_callables.get(callable_key)

        if entrypoint_raw:
            confined_bin = _confine_path_under_roots(entrypoint_raw, trusted_roots)
            capture = _is_path_under_dir(confined_bin, ws_resolved)
            actual_digest, pre_stat, verified_bytes = _read_regular_file_nofollow(confined_bin, capture_bytes=capture)
            if not hmac.compare_digest(normalize_sha256_hex(actual_digest), expected_hex):
                raise PermissionError("TOOL_BINARY_HASH_MISMATCH")
            return confined_bin, callable_fn, actual_digest, pre_stat, verified_bytes, expected_hex

        if callable_fn is not None:
            try:
                actual_digest = compute_callable_sha256(callable_fn)
            except ValueError as exc:
                raise PermissionError(str(exc)) from exc
            if not hmac.compare_digest(normalize_sha256_hex(actual_digest), expected_hex):
                raise PermissionError("TOOL_CALLABLE_HASH_MISMATCH")
            return None, callable_fn, actual_digest, None, None, expected_hex

        raise PermissionError("TOOL_NEITHER_ENTRYPOINT_NOR_ALLOWLISTED_CALLABLE")

    def _verify_binary_and_callable(
        self,
        tool_spec: Any,
        tool_id: str,
        ws_resolved: Path,
        security_context: Union[SecurityContext, Dict[str, Any]],
    ) -> Tuple[Optional[Path], Optional[Callable[..., Any]], str]:
        clean_spec = _normalize_tool_spec_for_runner(tool_spec)
        clean_ctx = (
            security_context
            if type(security_context) is dict
            else _normalize_security_context_for_runner(security_context)[0]
        )
        confined_bin, callable_fn, actual_digest, _, _, _ = self._verify_binary_and_callable_snapshot(
            clean_spec, tool_id, ws_resolved, clean_ctx
        )
        return confined_bin, callable_fn, actual_digest

    def _verify_toctou_snapshot(
        self,
        *,
        phase: str,
        raw_tool_spec: Any,
        tool_id: str,
        ws_resolved: Path,
        raw_security_context: Any,
        expected_runner_policy_hash: str,
        expected_hex: str,
        confined_bin: Optional[Path],
        pre_stat: Optional[Tuple[int, int, int]],
        callable_fn: Optional[Callable[..., Any]],
    ) -> None:
        """Re-verify policy hash, trust status, and binary/callable digest hook-free via `O_NOFOLLOW`."""
        live_ctx, _ = _normalize_security_context_for_runner(raw_security_context)
        try:
            live_spec = _normalize_tool_spec_for_runner(raw_tool_spec)
        except (TypeError, ValueError) as exc:
            raise PermissionError(f"TOCTOU_{phase}_SPEC_INVALID:{exc}") from exc

        cur_scars = self._load_scars(ws_resolved, live_ctx)
        cur_policy_hash = _compute_runner_policy_hash_from_dict(live_ctx, cur_scars)
        if not hmac.compare_digest(cur_policy_hash, expected_runner_policy_hash):
            raise PermissionError(f"TOCTOU_{phase}_POLICY_HASH_MISMATCH")

        trust_err, cur_tool_id, trust_reason = self._verify_trust_and_identity_normalized(live_spec)
        if trust_err is not None or cur_tool_id != tool_id:
            raise PermissionError(f"TOCTOU_{phase}_TRUST_CHANGED:{trust_reason}")

        spec_hex = normalize_sha256_hex(live_spec["binary_hash"])
        if not spec_hex or not hmac.compare_digest(spec_hex, expected_hex):
            raise PermissionError(f"TOCTOU_{phase}_SPEC_HASH_CHANGED")

        if confined_bin is not None:
            cur_digest, cur_stat, _ = _read_regular_file_nofollow(confined_bin, capture_bytes=False)
            if pre_stat is not None and (cur_stat[0], cur_stat[1]) != (pre_stat[0], pre_stat[1]):
                raise PermissionError(f"TOCTOU_{phase}_BINARY_INODE_CHANGED")
            if not hmac.compare_digest(normalize_sha256_hex(cur_digest), expected_hex):
                raise PermissionError(f"TOCTOU_{phase}_BINARY_HASH_CHANGED")

        if callable_fn is not None:
            try:
                cur_callable_digest = compute_callable_sha256(callable_fn)
            except ValueError as exc:
                raise PermissionError(f"TOCTOU_{phase}_{exc}") from exc
            if not hmac.compare_digest(normalize_sha256_hex(cur_callable_digest), expected_hex):
                raise PermissionError(f"TOCTOU_{phase}_CALLABLE_HASH_CHANGED")

    def _verify_permissions(
        self,
        tool_spec: Dict[str, Any],
        security_context: Dict[str, Any],
        argv_preview: Sequence[str],
    ) -> None:
        required = {p.strip().lower() for p in tool_spec["required_permissions"] if p.strip()}
        allowed = {p.strip().lower() for p in security_context["allowed_permissions"] if p.strip()}
        missing = sorted(required - allowed)
        if missing:
            raise PermissionError(f"MISSING_PERMISSIONS: {','.join(missing)}")

        runtime_reqs = tool_spec["runtime_requirements"]
        side_effects = {s.strip().lower() for s in tool_spec["side_effects"] if s.strip()}
        network_allowed = bool(security_context["network_allowed"])
        if self._config is not None and security_context["profile"] == SecurityProfile.GITHUB_PUBLIC.value:
            network_allowed = network_allowed and bool(self._config.github_public.network_access)

        if not network_allowed:
            if bool(runtime_reqs.get("network")):
                raise PermissionError("NETWORK_DISALLOWED_BY_CONTEXT")
            if (required | side_effects) & _NETWORK_PERMISSIONS or any(tok.startswith("network.") for tok in (required | side_effects)):
                raise PermissionError("NETWORK_PERMISSION_DISALLOWED_BY_CONTEXT")
            if argv_preview and os.path.basename(str(argv_preview[0])).lower() in _NETWORK_VERBS:
                raise PermissionError("NETWORK_EXECUTABLE_DISALLOWED_BY_CONTEXT")

        source_low = tool_spec["source"].strip().lower()
        sandbox_mandatory = source_low in {"forge_native", "forged"} or bool(runtime_reqs.get("sandbox_required"))
        if sandbox_mandatory and not argv_preview:
            raise PermissionError("OS_SANDBOX_REQUIRES_SUBPROCESS_EXEC")

        if not bool(security_context["allow_untrusted_native"]):
            if source_low in {"untrusted_native", "native_untrusted"} and not bool(runtime_reqs.get("sandbox_required")):
                raise PermissionError("UNTRUSTED_NATIVE_DISALLOWED_BY_CONTEXT")
            is_native = bool(
                runtime_reqs.get("native")
                or runtime_reqs.get("untrusted_native")
                or (required & _NATIVE_PERMISSIONS)
            )
            if is_native and not bool(runtime_reqs.get("sandbox_required")):
                raise PermissionError("UNTRUSTED_NATIVE_DISALLOWED_BY_CONTEXT")

    def _build_subprocess_argv(
        self,
        tool_spec: Dict[str, Any],
        confined_bin: Optional[Path],
        args: Dict[str, Any],
        explicit_argv: Optional[Sequence[str]],
        security_context: Dict[str, Any],
        ws_resolved: Path,
    ) -> List[str]:
        if explicit_argv is not None:
            tokens = [x for x in explicit_argv]
        else:
            template = list(tool_spec.get("command") or ())
            if template:
                tokens = []
                has_placeholder = False
                for tok in template:
                    tok_s = tok
                    if tok_s in ("{binary_path}", "{entrypoint}") and confined_bin is not None:
                        tokens.append(str(confined_bin))
                        has_placeholder = True
                    elif tok_s.startswith("{") and tok_s.endswith("}") and tok_s[1:-1] in args:
                        tokens.append(str(args[tok_s[1:-1]]))
                        has_placeholder = True
                    else:
                        tokens.append(tok_s)
                if not has_placeholder and type(args.get("argv")) is list:
                    tokens.extend(str(x) for x in args["argv"])
            elif confined_bin is not None:
                cli_args = [str(x) for x in args.get("argv", [])] if type(args.get("argv")) is list else []
                tokens = [sys.executable, str(confined_bin), *cli_args] if confined_bin.suffix == ".py" else [str(confined_bin), *cli_args]
            else:
                tokens = []

        if not tokens:
            raise PermissionError("EMPTY_EXECUTION_ARGV")
        if tokens[0] in ("python", "python3"):
            tokens[0] = sys.executable
        _collect_and_confine_paths(tokens[1:], security_context, ws_resolved, key_hint="argv")
        return tokens

    def _run_pre_tool_hooks(
        self,
        argv_tokens: Sequence[str],
        args: Dict[str, Any],
        scars: Sequence[GoldenScar],
        ws_resolved: Path,
    ) -> None:
        def _assert_allowed(payload: Dict[str, Any]) -> None:
            decision = evaluate_claude_pre_tool_payload(payload, scars, trusted_workspace_root=ws_resolved)
            if decision.get("decision") == "deny":
                raise PermissionError(str(decision.get("reason") or "PRETOOLUSE_HOOK_DENIED"))

        if argv_tokens:
            cmd_line = " ".join(shlex.quote(str(tok)) for tok in argv_tokens)
            _assert_allowed({"tool_name": "Bash", "tool_input": {"command": cmd_line, "cwd": str(ws_resolved)}})

        for cmd_key in ("command", "cmd", "shell_command"):
            if isinstance(args.get(cmd_key), str) and args[cmd_key].strip():
                _assert_allowed({"tool_name": "Bash", "tool_input": {"command": args[cmd_key], "cwd": str(ws_resolved)}})

        if "content" in args and any(k in args for k in ("file_path", "path", "output_path")):
            fpath = str(args.get("file_path") or args.get("path") or args.get("output_path") or "")
            _assert_allowed({"tool_name": "Write", "tool_input": {"file_path": fpath, "content": str(args.get("content") or "")}})

    def _execute_callable_in_process(
        self,
        fn: Callable[..., Any],
        args: Dict[str, Any],
        ws_resolved: Path,
        timeout: float,
    ) -> Tuple[int, Any, str, str, bool]:
        box: Dict[str, Any] = {"result": None, "error": None}

        def _target() -> None:
            try:
                params = inspect.signature(fn).parameters
                if "workspace_root" in params:
                    box["result"] = fn(args, workspace_root=ws_resolved)
                elif not params:
                    box["result"] = fn()
                else:
                    box["result"] = fn(args)
            except Exception as exc:
                box["error"] = exc

        worker = threading.Thread(target=_target, daemon=True)
        worker.start()
        worker.join(timeout=timeout)
        if worker.is_alive():
            return -1, None, "", "CALLABLE_EXECUTION_TIMEOUT", True
        if box["error"] is not None:
            return 1, None, "", f"{type(box['error']).__name__}: {box['error']}", False
        res = box["result"]
        stdout_text = res if isinstance(res, str) else json.dumps(res, ensure_ascii=False, default=str)
        return 0, res, stdout_text, "", False

    def _execute_callable_forked(
        self,
        fn: Callable[..., Any],
        args: Dict[str, Any],
        ws_resolved: Path,
        timeout: float,
        max_output_bytes: int,
        *,
        security_context: Optional[Union[SecurityContext, Dict[str, Any]]] = None,
    ) -> Tuple[int, Any, str, str, bool]:
        params = inspect.signature(fn).parameters
        eff_max_output = max(1024, int(max_output_bytes))
        if security_context is None:
            net_allowed = False
            allowed_perms = frozenset({"fs.read", "fs.write"})
        else:
            if type(security_context) is dict:
                ctx_dict = security_context
            else:
                try:
                    ctx_dict = extract_exact_security_context_dict(security_context)
                except (TypeError, ValueError) as exc:
                    raise PermissionError(str(exc)) from exc
            net_allowed = bool(ctx_dict.get("network_allowed", False))
            allowed_perms = frozenset(
                str(p).strip().lower()
                for p in (ctx_dict.get("allowed_permissions") or ())
                if str(p).strip()
            )
        read_fd, write_fd = os.pipe()
        execution_token = new_execution_token()
        pid = os.fork()
        if pid == 0:
            kernel_sandbox_active = False
            try:
                os.close(read_fd)
                os.setpgrp()
                write_fd = _sanitize_child_fds(write_fd, ws_resolved=ws_resolved)
                os.environ[EXEC_TOKEN_NAME] = execution_token
                os.chdir(str(ws_resolved))
                os.environ.pop("PYTHONPATH", None)
                os.environ["PYTHONNOUSERSITE"] = "1"
                os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
                os.environ["HOME"] = str(ws_resolved)
                os.environ["TMPDIR"] = str(ws_resolved)

                allow_exec = bool(allowed_perms & _AUDIT_EXEC_PERMISSIONS)
                if sys.platform == "darwin":
                    _apply_macos_seatbelt_in_child(ws_resolved)
                    kernel_sandbox_active = True
                elif sys.platform.startswith("linux"):
                    if not _apply_linux_landlock_in_child(ws_resolved, network_allowed=net_allowed):
                        _ll_ok, ll_errno = probe_linux_landlock_available()
                        raise PermissionError(f"SANDBOX_LINUX_LANDLOCK_FAILED:errno={ll_errno}")
                    if not net_allowed:
                        net_ok = _apply_linux_seccomp_network_deny_in_child(allow_exec=allow_exec)
                        if not net_ok:
                            net_ok = _apply_linux_netns_isolation_in_child()
                        if not net_ok:
                            raise PermissionError("SANDBOX_LINUX_NETWORK_ISOLATION_FAILED")
                    kernel_sandbox_active = True
                else:
                    raise PermissionError(f"SANDBOX_UNSUPPORTED_OS_PLATFORM:{sys.platform}")

                _install_child_audit_hook(
                    ws_resolved,
                    network_allowed=net_allowed,
                    allowed_permissions=allowed_perms,
                    kernel_sandbox_active=kernel_sandbox_active,
                )

                if "workspace_root" in params:
                    res = fn(args, workspace_root=ws_resolved)
                elif not params:
                    res = fn()
                else:
                    res = fn(args)
                envelope: Dict[str, Any] = {"ok": True, "res": _tagged_json_encode(res)}
            except Exception as exc:
                err_msg = f"{type(exc).__name__}: {exc}"
                is_sandbox_setup_err = (
                    not kernel_sandbox_active
                    or str(exc).startswith(
                        (
                            "SANDBOX_LINUX_",
                            "SEATBELT_CHILD_INIT_FAILED",
                            "SANDBOX_UNSUPPORTED_OS_PLATFORM",
                            "SANDBOX_FD_SANITIZE_FAILED",
                        )
                    )
                )
                envelope = {"ok": False, "err": err_msg, "sandbox_init_error": is_sandbox_setup_err}
            try:
                raw_payload = json.dumps(envelope, ensure_ascii=False, allow_nan=False).encode("utf-8")
                if len(raw_payload) > eff_max_output:
                    err_env = {"ok": False, "err": f"CALLABLE_OUTPUT_EXCEEDED_MAX_BYTES:{len(raw_payload)}>{eff_max_output}"}
                    raw_payload = json.dumps(err_env, ensure_ascii=False).encode("utf-8")
                view = memoryview(raw_payload)
                sent = 0
                while sent < len(raw_payload):
                    written = os.write(write_fd, view[sent:])
                    if written <= 0:
                        break
                    sent += written
            except OSError as _write_err:
                _ = _write_err
            finally:
                try:
                    os.close(write_fd)
                except OSError as _close_err:
                    _ = _close_err
                os._exit(0)

        # Parent process: enforce process-group isolation and bounded streaming read
        try:
            os.setpgid(pid, pid)
        except OSError as _pgid_err:
            _ = _pgid_err
        try:
            os.close(write_fd)
        except OSError as _wclose_err:
            _ = _wclose_err

        os.set_blocking(read_fd, False)
        selector = selectors.DefaultSelector()
        buf = bytearray()
        timed_out = False
        truncated = False
        child_reaped = False
        child_status = 0

        def _kill_and_reap() -> None:
            nonlocal child_reaped, child_status
            terminate_execution_tree(pid, execution_token)
            try:
                _, child_status = os.waitpid(pid, 0)
                child_reaped = True
            except ChildProcessError as _wait_err:
                _ = _wait_err
                child_reaped = True

        try:
            selector.register(read_fd, selectors.EVENT_READ)
            deadline = time.monotonic() + max(0.01, float(timeout))
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                events = selector.select(timeout=remaining)
                if not events:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    continue
                for key, _mask in events:
                    try:
                        chunk = os.read(key.fd, 8192)
                    except BlockingIOError as _bio_err:
                        _ = _bio_err
                        continue
                    except OSError as _read_err:
                        _ = _read_err
                        selector.unregister(key.fileobj)
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(buf) < eff_max_output:
                        take = min(len(chunk), eff_max_output - len(buf))
                        buf.extend(chunk[:take])
                        if take < len(chunk):
                            truncated = True
                    else:
                        truncated = True

            if timed_out:
                _kill_and_reap()
                return -1, None, "", "CALLABLE_EXECUTION_TIMEOUT", True

            wait_deadline = max(time.monotonic(), deadline)
            while not child_reaped:
                waited_pid, status = os.waitpid(pid, os.WNOHANG)
                if waited_pid == pid:
                    child_status = status
                    child_reaped = True
                    break
                if time.monotonic() >= wait_deadline:
                    _kill_and_reap()
                    return -1, None, "", "CALLABLE_EXECUTION_TIMEOUT", True
                time.sleep(0.002)
        finally:
            for key in list(selector.get_map().values()):
                try:
                    selector.unregister(key.fileobj)
                except (KeyError, ValueError) as _unreg_err:
                    _ = _unreg_err
            try:
                selector.close()
            except OSError as _sel_err:
                _ = _sel_err
            try:
                os.close(read_fd)
            except OSError as _rclose_err:
                _ = _rclose_err
            if not child_reaped:
                _kill_and_reap()

        if truncated:
            return 1, None, "", "CALLABLE_OUTPUT_TRUNCATED", False
        if not buf:
            if os.WIFSIGNALED(child_status):
                return 1, None, "", f"CALLABLE_CHILD_SIGNALED:{os.WTERMSIG(child_status)}", False
            return 1, None, "", "CALLABLE_EMPTY_PIPE_RESPONSE", False
        try:
            decoded_env = json.loads(buf.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            return 1, None, "", f"CALLABLE_INVALID_PIPE_JSON: {exc}", False
        if not isinstance(decoded_env, dict) or not decoded_env.get("ok"):
            err_txt = str(decoded_env.get("err") if isinstance(decoded_env, dict) else "CALLABLE_EXECUTION_ERROR")
            if isinstance(decoded_env, dict) and decoded_env.get("sandbox_init_error"):
                raise PermissionError(err_txt)
            return 1, None, "", err_txt, False
        res = _tagged_json_decode(decoded_env.get("res"))
        stdout_text = res if isinstance(res, str) else json.dumps(res, ensure_ascii=False, default=str)
        if len(stdout_text.encode("utf-8", errors="replace")) > eff_max_output:
            stdout_text = _decode_capped_utf8(stdout_text.encode("utf-8", errors="replace"), eff_max_output)
        return 0, res, stdout_text, "", False

    def _execute_callable_bounded(
        self,
        fn: Callable[..., Any],
        args: Dict[str, Any],
        ws_resolved: Path,
        timeout: float,
        max_output_bytes: Optional[int] = None,
        *,
        security_context: Optional[Union[SecurityContext, Dict[str, Any]]] = None,
    ) -> Tuple[int, Any, str, str, bool]:
        eff_max_output = max(1024, int(max_output_bytes if max_output_bytes is not None else self._max_output_bytes))
        if self._allow_in_process_callable or not hasattr(os, "fork"):
            return self._execute_callable_in_process(fn, args, ws_resolved, timeout)
        return self._execute_callable_forked(
            fn,
            args,
            ws_resolved,
            timeout,
            eff_max_output,
            security_context=security_context,
        )

    def _execute_subprocess_bounded(
        self,
        argv_tokens: List[str],
        ws_resolved: Path,
        timeout: float,
        max_output_bytes: int,
        stdin_text: Optional[Union[str, bytes]] = None,
    ) -> Tuple[int, Any, str, str, bool]:
        if stdin_text is None:
            stdin_bytes: Optional[bytes] = None
        elif isinstance(stdin_text, bytes):
            stdin_bytes = stdin_text
        else:
            stdin_bytes = str(stdin_text).encode("utf-8")
        try:
            exit_code, raw_out, raw_err, timed_out, _truncated = run_subprocess_streaming_bounded(
                argv_tokens,
                cwd=ws_resolved,
                env=_build_safe_env(ws_resolved),
                stdin_bytes=stdin_bytes,
                timeout_s=timeout,
                max_output_bytes=max_output_bytes,
            )
        except OSError as exc:
            return 1, None, "", f"SUBPROCESS_OS_ERROR: {exc}", False

        stdout_s = _decode_capped_utf8(raw_out, max_output_bytes)
        stderr_s = _decode_capped_utf8(raw_err, max_output_bytes)
        if timed_out:
            return -1, None, stdout_s, stderr_s or "SUBPROCESS_TIMEOUT", True
        parsed_out = _parse_json_output_if_applicable(stdout_s)
        return exit_code, parsed_out, stdout_s, stderr_s, False

    def _make_deny(
        self,
        *,
        run_id: str,
        task_id: str,
        tool_id: str,
        capability: str,
        status: ExecutionStatus,
        reason: str,
        plan_hash: str,
        tool_hash: str,
        policy_hash: str,
        environment_hash: str,
        t0: float,
        cpu0: float,
        extra_metrics: Optional[Mapping[str, Any]] = None,
    ) -> ExecutionReceipt:
        metrics: Dict[str, Any] = {
            "wall_time_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            "cpu_time_ms": round((time.process_time() - cpu0) * 1000.0, 3),
            "exit_code": -1,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "timed_out": False,
            "task_id": task_id,
            "tool_id": tool_id,
            "capability": capability,
            "error": reason,
        }
        if extra_metrics:
            metrics.update(dict(extra_metrics))
        return _build_receipt(
            run_id=run_id,
            status=status,
            verification_status="FAIL",
            exit_status=-1,
            plan_hash=plan_hash,
            tool_hash=tool_hash,
            policy_hash=policy_hash,
            environment_hash=environment_hash,
            artifact_digests={"stdout": sha256_digest(""), "stderr": sha256_digest("")},
            resource_metrics=metrics,
            stderr_excerpt=reason,
        )

    def run(
        self,
        tool_spec: Optional[Any],
        args: Optional[Dict[str, Any]] = None,
        security_context: Optional[SecurityContext] = None,
        *,
        oracle: Optional[Callable[..., Any]] = None,
        task_id: str = "",
        capability: str = "",
        plan_hash: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        argv: Optional[Sequence[str]] = None,
        expected_tool_hash: Optional[str] = None,
        expected_policy_hash: Optional[str] = None,
        expected_plan_hash: Optional[str] = None,
    ) -> ExecutionReceipt:
        """Execute a tool strictly inside `security_context` after hook-free normalization & TOCTOU checks."""
        if security_context is None:
            raise ValueError("SecurityContext is required for SecureRunner.run()")

        t0, cpu0 = time.perf_counter(), time.process_time()
        run_id = f"run_{secrets.token_hex(8)}"
        empty_tool_hash = sha256_digest("no_verified_tool")
        safe_task_id = task_id if type(task_id) is str else ""
        safe_capability = capability if type(capability) is str else ""
        static_fallback_plan = sha256_digest({"run_id": run_id, "phase": "entry_normalization"})
        static_fallback_policy = sha256_digest({"phase": "entry_normalization"})
        static_fallback_env = sha256_digest({"python": sys.version.split()[0], "platform": sys.platform})

        try:
            if type(task_id) is not str:
                raise TypeError("UNTRUSTED_TASK_ID_TYPE")
            if type(capability) is not str:
                raise TypeError("UNTRUSTED_CAPABILITY_TYPE")
            for opt_name, opt_val in (
                ("plan_hash", plan_hash),
                ("expected_tool_hash", expected_tool_hash),
                ("expected_policy_hash", expected_policy_hash),
                ("expected_plan_hash", expected_plan_hash),
            ):
                if opt_val is not None and type(opt_val) is not str:
                    raise TypeError(f"UNTRUSTED_{opt_name.upper()}_TYPE")
            if timeout_seconds is not None and type(timeout_seconds) is not int and type(timeout_seconds) is not float:
                raise TypeError("UNTRUSTED_TIMEOUT_SECONDS_TYPE")

            clean_argv: Optional[List[str]] = None
            if argv is not None:
                argv_t = type(argv)
                if argv_t is list:
                    argv_iter = list.__iter__(argv)
                elif argv_t is tuple:
                    argv_iter = tuple.__iter__(argv)
                else:
                    raise TypeError("UNTRUSTED_ARGV_TYPE")
                clean_argv = []
                for item in argv_iter:
                    if type(item) is not str:
                        raise TypeError("UNTRUSTED_ARGV_ELEMENT_TYPE")
                    clean_argv.append(item)

            if args is None:
                safe_args: Dict[str, Any] = {}
            elif type(args) is dict:
                safe_args = sanitize_exact_json_value(args, allow_bytes=True)
            else:
                raise TypeError("UNTRUSTED_ARGS_DICT_REQUIRED")

            clean_ctx, ctx_policy_hash = _normalize_security_context_for_runner(security_context)
            ws_resolved = Path(clean_ctx["workspace_root"]).resolve()
            scars = self._load_scars(ws_resolved, clean_ctx)
            policy_hash = _compute_runner_policy_hash_from_dict(clean_ctx, scars)
        except (TypeError, ValueError, PermissionError) as exc:
            return self._make_deny(
                run_id=run_id, task_id=safe_task_id, tool_id="", capability=safe_capability,
                status=ExecutionStatus.PERMISSION_DENIED, reason=str(exc),
                plan_hash=static_fallback_plan, tool_hash=empty_tool_hash,
                policy_hash=static_fallback_policy, environment_hash=static_fallback_env, t0=t0, cpu0=cpu0,
            )

        safe_explicit_plan = plan_hash.strip().lower() if (plan_hash and is_valid_sha256(plan_hash)) else None
        fallback_plan = safe_explicit_plan or sha256_digest({"task_id": safe_task_id, "args": redact_runtime_value(safe_args)})
        environment_hash = sha256_digest({
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "ws_digest": sha256_digest(str(ws_resolved)),
            "env_keys": sorted(_build_safe_env(ws_resolved).keys()),
        })

        try:
            clean_spec = _normalize_tool_spec_for_runner(tool_spec) if tool_spec is not None else None
        except (TypeError, ValueError, PermissionError) as exc:
            return self._make_deny(
                run_id=run_id, task_id=safe_task_id, tool_id="", capability=safe_capability,
                status=ExecutionStatus.PERMISSION_DENIED, reason=str(exc),
                plan_hash=fallback_plan, tool_hash=empty_tool_hash,
                policy_hash=policy_hash, environment_hash=environment_hash, t0=t0, cpu0=cpu0,
            )

        if plan_hash is not None and safe_explicit_plan is None:
            return self._make_deny(
                run_id=run_id, task_id=safe_task_id, tool_id=(clean_spec["tool_id"] if clean_spec is not None else ""),
                capability=safe_capability, status=ExecutionStatus.PERMISSION_DENIED, reason="INVALID_PLAN_HASH",
                plan_hash=fallback_plan, tool_hash=empty_tool_hash,
                policy_hash=policy_hash, environment_hash=environment_hash, t0=t0, cpu0=cpu0,
            )

        if expected_policy_hash is not None:
            exp_pol_hex = normalize_sha256_hex(expected_policy_hash)
            if not exp_pol_hex or not (
                hmac.compare_digest(exp_pol_hex, normalize_sha256_hex(ctx_policy_hash))
                or hmac.compare_digest(exp_pol_hex, normalize_sha256_hex(policy_hash))
            ):
                return self._make_deny(
                    run_id=run_id, task_id=safe_task_id, tool_id=(clean_spec["tool_id"] if clean_spec is not None else ""),
                    capability=safe_capability, status=ExecutionStatus.PERMISSION_DENIED, reason="EXPECTED_POLICY_HASH_MISMATCH",
                    plan_hash=fallback_plan, tool_hash=empty_tool_hash,
                    policy_hash=policy_hash, environment_hash=environment_hash, t0=t0, cpu0=cpu0,
                )

        trust_err_status, tool_id, trust_reason = self._verify_trust_and_identity_normalized(clean_spec)
        computed_plan_hash = safe_explicit_plan or sha256_digest({
            "task_id": safe_task_id, "capability": safe_capability, "tool_id": tool_id, "args": redact_runtime_value(safe_args),
        })
        if expected_plan_hash is not None:
            exp_plan_hex = normalize_sha256_hex(expected_plan_hash)
            if not exp_plan_hex or not hmac.compare_digest(exp_plan_hex, normalize_sha256_hex(computed_plan_hash)):
                return self._make_deny(
                    run_id=run_id, task_id=safe_task_id, tool_id=tool_id, capability=safe_capability,
                    status=ExecutionStatus.PERMISSION_DENIED, reason="EXPECTED_PLAN_HASH_MISMATCH",
                    plan_hash=computed_plan_hash, tool_hash=empty_tool_hash,
                    policy_hash=policy_hash, environment_hash=environment_hash, t0=t0, cpu0=cpu0,
                )

        if trust_err_status is not None or clean_spec is None:
            return self._make_deny(
                run_id=run_id, task_id=safe_task_id, tool_id=tool_id, capability=safe_capability,
                status=trust_err_status or ExecutionStatus.NO_VERIFIED_TOOL, reason=trust_reason or "TOOL_NOT_FOUND",
                plan_hash=computed_plan_hash, tool_hash=empty_tool_hash,
                policy_hash=policy_hash, environment_hash=environment_hash, t0=t0, cpu0=cpu0,
            )

        tool_hash = empty_tool_hash
        stage_dir: Optional[Path] = None
        sandbox_receipt_dict: Optional[Dict[str, Any]] = None
        try:
            confined_bin, callable_fn, tool_hash, pre_stat, verified_bytes, expected_hex = (
                self._verify_binary_and_callable_snapshot(clean_spec, tool_id, ws_resolved, clean_ctx)
            )
            if expected_tool_hash is not None:
                exp_tool_hex = normalize_sha256_hex(expected_tool_hash)
                if not exp_tool_hex or not hmac.compare_digest(exp_tool_hex, normalize_sha256_hex(tool_hash)):
                    raise PermissionError("EXPECTED_TOOL_HASH_MISMATCH")

            _collect_and_confine_paths(safe_args, clean_ctx, ws_resolved)
            has_cmd = bool(clean_spec.get("command"))
            argv_tokens: List[str] = (
                self._build_subprocess_argv(clean_spec, confined_bin, safe_args, clean_argv, clean_ctx, ws_resolved)
                if (callable_fn is None or clean_argv is not None or has_cmd)
                else []
            )
            self._verify_permissions(clean_spec, clean_ctx, argv_tokens)
            self._run_pre_tool_hooks(argv_tokens, safe_args, scars, ws_resolved)

            self._verify_toctou_snapshot(
                phase="PRE_EXEC",
                raw_tool_spec=tool_spec,
                tool_id=tool_id,
                ws_resolved=ws_resolved,
                raw_security_context=security_context,
                expected_runner_policy_hash=policy_hash,
                expected_hex=expected_hex,
                confined_bin=confined_bin,
                pre_stat=pre_stat,
                callable_fn=callable_fn,
            )

            exec_argv = list(argv_tokens)
            entrypoint_str = clean_spec.get("entrypoint") or ""
            if (
                confined_bin is not None
                and verified_bytes is not None
                and exec_argv
                and _is_path_under_dir(confined_bin, ws_resolved)
                and (str(confined_bin) in exec_argv or (entrypoint_str and entrypoint_str in exec_argv))
            ):
                stage_dir, staged_path = _stage_verified_binary(
                    confined_bin, verified_bytes, expected_hex, ws_resolved=ws_resolved
                )
                exec_argv = [
                    str(staged_path) if (tok == str(confined_bin) or (entrypoint_str and tok == entrypoint_str)) else tok
                    for tok in exec_argv
                ]

            runtime_reqs = clean_spec["runtime_requirements"]
            ctx_max_timeout = self._default_timeout_seconds
            spec_timeout = runtime_reqs.get("timeout_seconds")
            if spec_timeout is not None and type(spec_timeout) is not int and type(spec_timeout) is not float:
                raise PermissionError("INVALID_RUNTIME_REQUIREMENTS_TIMEOUT")
            req_timeout = (
                timeout_seconds
                if timeout_seconds is not None
                else (float(spec_timeout) if spec_timeout is not None else self._default_timeout_seconds)
            )
            effective_timeout = max(0.01, min(float(req_timeout), ctx_max_timeout))
            max_out_bytes = self._max_output_bytes
            sandbox_mandatory = self._is_sandbox_mandatory(clean_spec)

            if callable_fn is not None and not exec_argv:
                raw_cname = runtime_reqs.get("callable_name")
                callable_key = raw_cname.strip() if (type(raw_cname) is str and raw_cname.strip()) else tool_id
                trusted_host_source = clean_spec["source"].strip().lower() in {
                    "builtin", "builtin_allowlist", "host_trusted"
                }
                binding = self._trusted_host_callable_bindings.get(callable_key)
                trusted_host_registered = callable_key in self._trusted_host_callable_ids
                if sandbox_mandatory or not (
                    self._allow_trusted_host_callables and trusted_host_registered and trusted_host_source
                ):
                    return self._make_deny(
                        run_id=run_id, task_id=safe_task_id, tool_id=tool_id, capability=safe_capability,
                        status=ExecutionStatus.SANDBOX_UNAVAILABLE,
                        reason="OS_SANDBOX_REQUIRED_FOR_UNTRUSTED_CALLABLE",
                        plan_hash=computed_plan_hash, tool_hash=tool_hash,
                        policy_hash=policy_hash, environment_hash=environment_hash, t0=t0, cpu0=cpu0,
                    )
                try:
                    live_bind_digest = compute_callable_sha256(callable_fn)
                except ValueError as exc:
                    raise PermissionError(str(exc)) from exc
                if (
                    binding is None
                    or binding.get("fn") is not callable_fn
                    or not hmac.compare_digest(live_bind_digest, str(binding.get("callable_hash") or ""))
                ):
                    return self._make_deny(
                        run_id=run_id, task_id=safe_task_id, tool_id=tool_id, capability=safe_capability,
                        status=ExecutionStatus.PERMISSION_DENIED,
                        reason="TRUSTED_HOST_CALLABLE_BINDING_MISMATCH",
                        plan_hash=computed_plan_hash, tool_hash=tool_hash,
                        policy_hash=policy_hash, environment_hash=environment_hash, t0=t0, cpu0=cpu0,
                    )
                bound_digest = binding.get("bound_spec_digest")
                if bound_digest is not None:
                    live_spec_digest = compute_tool_spec_security_digest(clean_spec)
                    if not hmac.compare_digest(live_spec_digest, str(bound_digest)):
                        return self._make_deny(
                            run_id=run_id, task_id=safe_task_id, tool_id=tool_id, capability=safe_capability,
                            status=ExecutionStatus.PERMISSION_DENIED,
                            reason="TRUSTED_HOST_CALLABLE_SPEC_DIGEST_MISMATCH",
                            plan_hash=computed_plan_hash, tool_hash=tool_hash,
                            policy_hash=policy_hash, environment_hash=environment_hash, t0=t0, cpu0=cpu0,
                        )
                bound_perms = binding.get("required_permissions")
                if bound_perms is not None:
                    spec_perms = {p.strip().lower() for p in clean_spec["required_permissions"] if p.strip()}
                    ctx_perms = {p.strip().lower() for p in clean_ctx["allowed_permissions"] if p.strip()}
                    if not bound_perms.issubset(spec_perms) or not bound_perms.issubset(ctx_perms):
                        return self._make_deny(
                            run_id=run_id, task_id=safe_task_id, tool_id=tool_id, capability=safe_capability,
                            status=ExecutionStatus.PERMISSION_DENIED,
                            reason="TRUSTED_HOST_CALLABLE_PERMISSION_MISMATCH",
                            plan_hash=computed_plan_hash, tool_hash=tool_hash,
                            policy_hash=policy_hash, environment_hash=environment_hash, t0=t0, cpu0=cpu0,
                        )
                exit_code, raw_output, stdout_raw, stderr_raw, timed_out = self._execute_callable_bounded(
                    callable_fn,
                    safe_args,
                    ws_resolved,
                    effective_timeout,
                    max_output_bytes=max_out_bytes,
                    security_context=clean_ctx,
                )
            else:
                raw_stdin = safe_args.get("stdin")
                stdin_payload: Optional[Union[str, bytes]] = (
                    raw_stdin if (type(raw_stdin) is bytes or type(raw_stdin) is str) else None
                )
                if sandbox_mandatory or self._require_os_sandbox:
                    sb = self._get_sandbox(ws_resolved)
                    sb_res = sb.execute(
                        exec_argv,
                        stdin_data=stdin_payload,
                        timeout_s=effective_timeout,
                        env_overrides=None,
                        cwd=ws_resolved,
                        max_output_bytes=max_out_bytes,
                    )
                    sandbox_receipt_dict = sb_res.receipt.to_dict()
                    if sb_res.execution_status == ExecutionStatus.SANDBOX_UNAVAILABLE:
                        unavail_reason = sb_res.receipt.reason or sb_res.stderr or "SANDBOX_UNAVAILABLE"
                        return self._make_deny(
                            run_id=run_id,
                            task_id=safe_task_id,
                            tool_id=tool_id,
                            capability=safe_capability,
                            status=ExecutionStatus.SANDBOX_UNAVAILABLE,
                            reason=unavail_reason,
                            plan_hash=computed_plan_hash,
                            tool_hash=tool_hash,
                            policy_hash=policy_hash,
                            environment_hash=environment_hash,
                            t0=t0,
                            cpu0=cpu0,
                            extra_metrics={"sandbox_receipt": sandbox_receipt_dict},
                        )
                    exit_code = int(sb_res.exit_code)
                    timed_out = bool(sb_res.timed_out)
                    stdout_raw = _decode_capped_utf8(sb_res.stdout.encode("utf-8", errors="replace"), max_out_bytes)
                    stderr_raw = _decode_capped_utf8(sb_res.stderr.encode("utf-8", errors="replace"), max_out_bytes)
                    raw_output = None if timed_out else _parse_json_output_if_applicable(stdout_raw)
                else:
                    exit_code, raw_output, stdout_raw, stderr_raw, timed_out = self._execute_subprocess_bounded(
                        exec_argv, ws_resolved, effective_timeout, max_out_bytes, stdin_text=stdin_payload
                    )

            self._verify_toctou_snapshot(
                phase="POST_EXEC",
                raw_tool_spec=tool_spec,
                tool_id=tool_id,
                ws_resolved=ws_resolved,
                raw_security_context=security_context,
                expected_runner_policy_hash=policy_hash,
                expected_hex=expected_hex,
                confined_bin=confined_bin,
                pre_stat=pre_stat,
                callable_fn=callable_fn,
            )
        except PermissionError as exc:
            return self._make_deny(
                run_id=run_id, task_id=safe_task_id, tool_id=tool_id, capability=safe_capability,
                status=ExecutionStatus.PERMISSION_DENIED, reason=str(exc),
                plan_hash=computed_plan_hash, tool_hash=tool_hash,
                policy_hash=policy_hash, environment_hash=environment_hash, t0=t0, cpu0=cpu0,
            )
        finally:
            if stage_dir is not None:
                shutil.rmtree(stage_dir, ignore_errors=True)

        receipt_status, verification_status, oracle_reason, error_msg = self._evaluate_outcome(
            exit_code=exit_code, timed_out=timed_out, raw_output=raw_output,
            stdout_raw=stdout_raw, stderr_raw=stderr_raw, ws_resolved=ws_resolved,
            oracle=oracle, tool_spec=clean_spec, safe_args=safe_args, security_context=clean_ctx,
        )

        safe_digest_output = _json_safe_output(raw_output)
        artifact_digests: Dict[str, str] = {
            "stdout": sha256_digest(stdout_raw),
            "stderr": sha256_digest(stderr_raw),
            "output": sha256_digest(safe_digest_output),
        }
        for out_key in ("output_path", "out_path", "output_file"):
            out_arg = safe_args.get(out_key)
            if type(out_arg) is str:
                try:
                    _, out_digest = compute_file_sha256_confined(Path(out_arg), (ws_resolved,))
                    artifact_digests[out_key] = out_digest
                except PermissionError as _file_err:
                    _ = _file_err

        final_metrics: Dict[str, Any] = {
            "wall_time_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            "cpu_time_ms": round((time.process_time() - cpu0) * 1000.0, 3),
            "exit_code": exit_code,
            "stdout_bytes": len(stdout_raw.encode("utf-8", errors="replace")),
            "stderr_bytes": len(stderr_raw.encode("utf-8", errors="replace")),
            "timed_out": timed_out,
            "task_id": safe_task_id,
            "tool_id": tool_id,
            "capability": safe_capability,
            "oracle_reason": oracle_reason,
            "error": error_msg,
            "output": redact_runtime_value(safe_digest_output),
        }
        if sandbox_receipt_dict is not None:
            final_metrics["sandbox_receipt"] = sandbox_receipt_dict

        return _build_receipt(
            run_id=run_id,
            status=receipt_status,
            verification_status=verification_status,
            exit_status=exit_code,
            plan_hash=computed_plan_hash,
            tool_hash=tool_hash,
            policy_hash=policy_hash,
            environment_hash=environment_hash,
            artifact_digests=artifact_digests,
            resource_metrics=final_metrics,
            stdout_excerpt=stdout_raw,
            stderr_excerpt=error_msg or stderr_raw,
        )

    def _evaluate_outcome(
        self,
        *,
        exit_code: int,
        timed_out: bool,
        raw_output: Any,
        stdout_raw: str,
        stderr_raw: str,
        ws_resolved: Path,
        oracle: Optional[Callable[..., Any]],
        tool_spec: Any,
        safe_args: Dict[str, Any],
        security_context: Union[SecurityContext, Dict[str, Any]],
    ) -> Tuple[ExecutionStatus, str, str, Optional[str]]:
        if timed_out:
            return ExecutionStatus.FAIL, "FAIL", "EXECUTION_TIMED_OUT", "EXECUTION_TIMED_OUT"
        if exit_code != 0:
            return ExecutionStatus.FAIL, "FAIL", f"NON_ZERO_EXIT_CODE:{exit_code}", stderr_raw.strip() or f"EXIT_CODE_{exit_code}"
        if oracle is None:
            return ExecutionStatus.NOT_VERIFIED, "NOT_VERIFIED", "NO_ORACLE_PROVIDED", None
        exec_summary = {
            "status": "SUCCEEDED",
            "exit_code": exit_code,
            "output": raw_output,
            "stdout": stdout_raw,
            "stderr": stderr_raw,
            "workspace_root": str(ws_resolved),
        }
        passed, oracle_reason = _invoke_oracle(oracle, exec_summary, tool_spec, safe_args, security_context)
        return (ExecutionStatus.PASS, "PASS", oracle_reason, None) if passed else (ExecutionStatus.FAIL, "FAIL", oracle_reason, None)
