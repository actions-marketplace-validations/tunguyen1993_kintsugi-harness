"""Security & isolation test suite for Build #3 Hermetic Spawn Worker (`kintsugi.runtime.hermetic_worker`)."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import types
import unittest
import unittest.mock
from pathlib import Path, PosixPath
from typing import Any, Dict

import kintsugi.runtime.hermetic_worker as hermetic_worker_mod

from kintsugi.capability.schemas import (
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    sha256_digest,
)
from kintsugi.runtime.hermetic_worker import (
    HermeticEntrypointSpec,
    HermeticSpawnRunner,
    _sanitize_worker_fds,
    probe_linux_landlock_available,
)


def _sha256_file(path: Path) -> str:
    return sha256_digest(path.read_bytes())


class TestHermeticWorker(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.ws = self.root / "ws"
        self.ws.mkdir()
        os.chmod(self.ws, 0o700)
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "fs.write"],
            network_allowed=False,
        )
        self.runner = HermeticSpawnRunner()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _expect_linux_landlock_unavailable(self) -> bool:
        return sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]

    def test_clean_module_execution_returns_exact_output_and_receipt(self) -> None:
        tool_file = self.ws / "clean_math.py"
        tool_file.write_text(
            "import json\n"
            "import math\n"
            "from pathlib import Path\n\n"
            "def compute(payload, workspace_root=None):\n"
            "    out_p = Path(workspace_root) / 'artifact.json'\n"
            "    res = {'sum': payload['a'] + payload['b'], 'sqrt16': int(math.isqrt(16))}\n"
            "    out_p.write_text(json.dumps(res, sort_keys=True), encoding='utf-8')\n"
            "    print('HERMETIC_STDOUT_OK')\n"
            "    return res\n",
            encoding="utf-8",
        )
        expected_sha = _sha256_file(tool_file)
        spec = HermeticEntrypointSpec(
            tool_id="b3.clean_math",
            module_path="clean_math",
            callable_attr="compute",
            expected_module_file_sha256=expected_sha,
            module_file_path=tool_file,
        )

        res = self.runner.run(
            spec,
            {"a": 19, "b": 23},
            security_context=self.ctx,
            oracle=lambda summary: summary["output"] == {"sum": 42, "sqrt16": 4},
            task_id="task-b3-1",
            capability="math.add",
        )

        if self._expect_linux_landlock_unavailable():
            self.assertIn(
                res.execution_status,
                (ExecutionStatus.SANDBOX_UNAVAILABLE, ExecutionStatus.PERMISSION_DENIED),
            )
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", res.receipt.stderr_excerpt)
            return

        self.assertTrue(res.passed, res.error or res.stderr)
        self.assertEqual(res.execution_status, ExecutionStatus.PASS)
        self.assertEqual(res.receipt.status, ExecutionStatus.PASS)
        self.assertTrue(res.isolated)
        self.assertTrue(res.worker_spawned)
        self.assertEqual(res.output, {"sum": 42, "sqrt16": 4})
        self.assertIn("HERMETIC_STDOUT_OK", res.stdout)
        self.assertGreater(res.wall_time_ms, 0.0)
        self.assertEqual(res.pinned_module_sha256, expected_sha)
        self.assertIsNotNone(res.pinned_inode)
        self.assertEqual(res.receipt.tool_hash, expected_sha)
        self.assertEqual(res.receipt.llm_calls, 0)
        self.assertTrue((self.ws / "artifact.json").exists())

        # Also verify auto-resolution without explicit module_file_path via allowed_roots (read-only).
        ro_root = self.root / "ro_tools"
        pkg_dir = ro_root / "pkg_tools"
        pkg_dir.mkdir(parents=True)
        ro_mod = pkg_dir / "ro_echo.py"
        ro_mod.write_text(
            "from pathlib import Path\n"
            "def echo(payload):\n"
            "    try:\n"
            "        Path(payload['ro_escape']).write_text('escape', encoding='utf-8')\n"
            "        ro_blocked = False\n"
            "    except PermissionError:\n"
            "        ro_blocked = True\n"
            "    return {'echo': payload['msg'], 'ro_write_blocked': ro_blocked}\n",
            encoding="utf-8",
        )
        ro_runner = HermeticSpawnRunner(allowed_roots=[ro_root])
        ro_spec = HermeticEntrypointSpec(
            tool_id="b3.ro_echo",
            module_path="pkg_tools.ro_echo",
            callable_attr="echo",
            expected_module_file_sha256=_sha256_file(ro_mod),
        )
        ro_escape_target = ro_root / "ro_escape.txt"
        ro_res = ro_runner.run(
            ro_spec,
            {"msg": "hermetic", "ro_escape": str(ro_escape_target)},
            security_context=self.ctx,
        )
        self.assertTrue(ro_res.passed, ro_res.error or ro_res.stderr)
        self.assertEqual(ro_res.output, {"echo": "hermetic", "ro_write_blocked": True})
        self.assertFalse(ro_escape_target.exists())

    def test_host_isolation_and_zero_preflight_dunder_hooks(self) -> None:
        outside_canary = self.root / "host_preflight_canary.txt"

        class EvilBoolModule(types.ModuleType):
            def __bool__(self) -> bool:
                outside_canary.write_text("PWNED_MODULE_BOOL", encoding="utf-8")
                return True

        class EvilTrapObj:
            def __bool__(self) -> bool:
                outside_canary.write_text("PWNED_OBJ_BOOL", encoding="utf-8")
                return True

            def __eq__(self, other: Any) -> bool:
                outside_canary.write_text("PWNED_OBJ_EQ", encoding="utf-8")
                return False

            def __getattribute__(self, name: str) -> Any:
                outside_canary.write_text(f"PWNED_OBJ_GETATTR:{name}", encoding="utf-8")
                raise AttributeError(name)

            def __str__(self) -> str:
                outside_canary.write_text("PWNED_OBJ_STR", encoding="utf-8")
                return "EVIL"

        host_only_mod = EvilBoolModule("kintsugi_secret_host_only_mod")
        host_only_mod.UNEXPORTED_HOST_SECRET = "_".join(["HOST", "MEMORY", "SECRET", "XYZ", "999"])  # type: ignore[attr-defined]
        sys.modules["kintsugi_secret_host_only_mod"] = host_only_mod

        tool_file = self.ws / "env_probe.py"
        tool_file.write_text(
            "import os\n"
            "import sys\n\n"
            "def inspect_worker(payload):\n"
            "    return {\n"
            "        'has_host_secret_env': 'SUPER_HOST_SECRET' in os.environ,\n"
            "        'has_openai_key': 'OPENAI_API_KEY' in os.environ,\n"
            "        'has_pythonpath': 'PYTHONPATH' in os.environ,\n"
            "        'has_pythonhome': 'PYTHONHOME' in os.environ,\n"
            "        'has_pythoninspect': 'PYTHONINSPECT' in os.environ,\n"
            "        'has_pythonstartup': 'PYTHONSTARTUP' in os.environ,\n"
            "        'has_ld_preload': 'LD_PRELOAD' in os.environ,\n"
            "        'has_dyld_insert': 'DYLD_INSERT_LIBRARIES' in os.environ,\n"
            "        'has_http_proxy': 'HTTP_PROXY' in os.environ,\n"
            "        'dont_write_bytecode': os.environ.get('PYTHONDONTWRITEBYTECODE'),\n"
            "        'no_user_site': os.environ.get('PYTHONNOUSERSITE'),\n"
            "        'has_exec_token': bool(os.environ.get('KINTSUGI_EXEC_TOKEN')),\n"
            "        'has_host_sys_mod': 'kintsugi_secret_host_only_mod' in sys.modules,\n"
            "        'sys_path_has_evil': any('/evil_host_site' in p for p in sys.path),\n"
            "        'argv_len': len(sys.argv),\n"
            "        'echo': payload['tag'],\n"
            "    }\n",
            encoding="utf-8",
        )
        spec = HermeticEntrypointSpec(
            tool_id="b3.env_probe",
            module_path="env_probe",
            callable_attr="inspect_worker",
            expected_module_file_sha256=_sha256_file(tool_file),
            module_file_path=tool_file,
        )

        evil_env = {
            "SUPER_HOST_SECRET": "-".join(["canary", "host", "only", "secret", "0001"]),
            "OPENAI_API_KEY": "-".join(["canary", "host", "api", "secret", "0002"]),
            "PYTHONPATH": "/evil_host_site",
            "PYTHONHOME": "/evil_python_home",
            "PYTHONINSPECT": "1",
            "PYTHONSTARTUP": str(outside_canary),
            "LD_PRELOAD": "/evil/lib.so",
            "DYLD_INSERT_LIBRARIES": "/evil/lib.dylib",
            "HTTP_PROXY": "http://127.0.0.1:9999",
        }
        try:
            with unittest.mock.patch.dict(os.environ, evil_env, clear=False):
                with unittest.mock.patch("os.fork", side_effect=AssertionError("os.fork must never be called")):
                    res = self.runner.run(spec, {"tag": "isolated"}, security_context=self.ctx)

                    # Also verify passing EvilTrapObj directly in payload never executes dunders in preflight.
                    trap_res = self.runner.run(spec, {"bad": EvilTrapObj()}, security_context=self.ctx)
        finally:
            sys.modules.pop("kintsugi_secret_host_only_mod", None)

        self.assertFalse(outside_canary.exists(), "Host preflight triggered malicious dunder hook!")
        self.assertEqual(trap_res.execution_status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(trap_res.worker_spawned)

        if self._expect_linux_landlock_unavailable():
            self.assertIn(
                res.execution_status,
                (ExecutionStatus.SANDBOX_UNAVAILABLE, ExecutionStatus.PERMISSION_DENIED),
            )
            return

        self.assertTrue(res.passed, res.error or res.stderr)
        out = res.output
        self.assertFalse(out["has_host_secret_env"])
        self.assertFalse(out["has_openai_key"])
        self.assertFalse(out["has_pythonpath"])
        self.assertFalse(out["has_pythonhome"])
        self.assertFalse(out["has_pythoninspect"])
        self.assertFalse(out["has_pythonstartup"])
        self.assertFalse(out["has_ld_preload"])
        self.assertFalse(out["has_dyld_insert"])
        self.assertFalse(out["has_http_proxy"])
        self.assertEqual(out["dont_write_bytecode"], "1")
        self.assertEqual(out["no_user_site"], "1")
        self.assertTrue(out["has_exec_token"])
        self.assertFalse(out["has_host_sys_mod"])
        self.assertFalse(out["sys_path_has_evil"])
        self.assertEqual(out["argv_len"], 1)
        self.assertEqual(out["echo"], "isolated")

    def test_tamper_toctou_symlink_hardlink_pin_rejection_without_spawn(self) -> None:
        outside_target = self.root / "outside_tool.py"
        outside_target.write_text("def run(_p): return {'pwned': True}\n", encoding="utf-8")
        outside_sha = _sha256_file(outside_target)

        # 1. Wrong SHA-256 -> fail closed without spawning worker
        good_file = self.ws / "good_mod.py"
        good_file.write_text("def run(p): return {'ok': True}\n", encoding="utf-8")
        bad_hash_spec = HermeticEntrypointSpec(
            tool_id="b3.bad_sha",
            module_path="good_mod",
            callable_attr="run",
            expected_module_file_sha256="sha256:" + "0" * 64,
            module_file_path=good_file,
        )
        with unittest.mock.patch("subprocess.Popen") as mock_popen:
            res_sha = self.runner.run(bad_hash_spec, {}, security_context=self.ctx)
            mock_popen.assert_not_called()
        self.assertEqual(res_sha.execution_status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(res_sha.worker_spawned)
        self.assertIn("MODULE_FILE_SHA256_MISMATCH", res_sha.error)

        # 2. Symlink module file -> fail closed without spawning worker
        sym_file = self.ws / "sym_mod.py"
        sym_file.symlink_to(outside_target)
        sym_spec = HermeticEntrypointSpec(
            tool_id="b3.sym_mod",
            module_path="sym_mod",
            callable_attr="run",
            expected_module_file_sha256=outside_sha,
            module_file_path=sym_file,
        )
        with unittest.mock.patch("subprocess.Popen") as mock_popen:
            res_sym = self.runner.run(sym_spec, {}, security_context=self.ctx)
            mock_popen.assert_not_called()
        self.assertEqual(res_sym.execution_status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(res_sym.worker_spawned)

        # 3. Symlink parent directory inside workspace -> fail closed without spawning worker
        sym_dir = self.ws / "linked_dir"
        sym_dir.symlink_to(self.root)
        sym_dir_spec = HermeticEntrypointSpec(
            tool_id="b3.sym_dir",
            module_path="outside_tool",
            callable_attr="run",
            expected_module_file_sha256=outside_sha,
            module_file_path=sym_dir / "outside_tool.py",
        )
        with unittest.mock.patch("subprocess.Popen") as mock_popen:
            res_sdir = self.runner.run(sym_dir_spec, {}, security_context=self.ctx)
            mock_popen.assert_not_called()
        self.assertEqual(res_sdir.execution_status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(res_sdir.worker_spawned)

        # 4. Hardlink inside workspace (`st_nlink == 2`) -> fail closed without spawning worker
        hard_file = self.ws / "hard_mod.py"
        os.link(outside_target, hard_file)
        hard_spec = HermeticEntrypointSpec(
            tool_id="b3.hard_mod",
            module_path="hard_mod",
            callable_attr="run",
            expected_module_file_sha256=outside_sha,
            module_file_path=hard_file,
        )
        with unittest.mock.patch("subprocess.Popen") as mock_popen:
            res_hard = self.runner.run(hard_spec, {}, security_context=self.ctx)
            mock_popen.assert_not_called()
        self.assertEqual(res_hard.execution_status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(res_hard.worker_spawned)
        self.assertIn("SECURITY_HARDLINK_FORBIDDEN", res_hard.error)

        # 5. Outside workspace file path -> fail closed without spawning worker
        outside_spec = HermeticEntrypointSpec(
            tool_id="b3.outside_mod",
            module_path="outside_tool",
            callable_attr="run",
            expected_module_file_sha256=outside_sha,
            module_file_path=outside_target,
        )
        with unittest.mock.patch("subprocess.Popen") as mock_popen:
            res_out = self.runner.run(outside_spec, {}, security_context=self.ctx)
            mock_popen.assert_not_called()
        self.assertEqual(res_out.execution_status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(res_out.worker_spawned)

        # 6. Pre-spawn to in-worker TOCTOU swap -> worker detects inode/hash change and fails closed
        toctou_file = self.ws / "toctou_mod.py"
        toctou_file.write_text("def run(_p): return {'clean': True}\n", encoding="utf-8")
        toctou_sha = _sha256_file(toctou_file)
        toctou_spec = HermeticEntrypointSpec(
            tool_id="b3.toctou",
            module_path="toctou_mod",
            callable_attr="run",
            expected_module_file_sha256=toctou_sha,
            module_file_path=toctou_file,
        )
        evil_marker = self.ws / "swapped_code_ran.txt"
        orig_spawn = self.runner._spawn_and_communicate

        def _swap_before_spawn(*args: Any, **kwargs: Any) -> Any:
            tmp_swap = self.ws / "toctou_swap.py"
            tmp_swap.write_text(
                f"from pathlib import Path\ndef run(_p):\n    Path({str(evil_marker)!r}).write_text('SWAPPED')\n    return {{'swapped': True}}\n",
                encoding="utf-8",
            )
            os.replace(tmp_swap, toctou_file)
            return orig_spawn(*args, **kwargs)

        with unittest.mock.patch.object(self.runner, "_spawn_and_communicate", side_effect=_swap_before_spawn):
            res_toctou = self.runner.run(toctou_spec, {}, security_context=self.ctx)
        self.assertNotEqual(res_toctou.execution_status, ExecutionStatus.PASS)
        self.assertFalse(evil_marker.exists(), "Swapped code executed despite worker TOCTOU pin!")

        # 7. Post-exec TOCTOU detection if module self-mutates during execution
        self_mod_file = self.ws / "self_mut.py"
        self_mod_file.write_text(
            f"from pathlib import Path\ndef run(_p):\n    Path({str(self_mod_file)!r}).write_text('# mutated\\n', encoding='utf-8')\n    return {{'done': True}}\n",
            encoding="utf-8",
        )
        self_mod_spec = HermeticEntrypointSpec(
            tool_id="b3.self_mut",
            module_path="self_mut",
            callable_attr="run",
            expected_module_file_sha256=_sha256_file(self_mod_file),
            module_file_path=self_mod_file,
        )
        res_mut = self.runner.run(self_mod_spec, {}, security_context=self.ctx)
        if not self._expect_linux_landlock_unavailable():
            self.assertEqual(res_mut.execution_status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("TOCTOU_POST_EXEC_", res_mut.error)

    def test_os_sandbox_blocks_outside_read_write_network_and_disallowed_imports(self) -> None:
        outside_secret = self.root / "outside_secret.txt"
        canary = "OUTSIDE_SECRET_CANARY_B3_7741"
        outside_secret.write_text(canary, encoding="utf-8")
        os.chmod(outside_secret, 0o644)
        outside_write = self.root / "outside_escape_write.txt"

        (self.ws / "allowed_helper.py").write_text("VALUE = 123\n", encoding="utf-8")
        (self.ws / "forbidden_sibling.py").write_text("SECRET = 999\n", encoding="utf-8")
        (self.ws / "ws_escape_link.txt").symlink_to(outside_secret)

        probe_file = self.ws / "sandbox_probe.py"
        probe_file.write_text(
            "import errno\n"
            "import socket\n"
            "import subprocess\n"
            "import sys\n"
            "from pathlib import Path\n"
            "import allowed_helper\n\n"
            "def probe(payload):\n"
            "    results = {'allowed_helper': allowed_helper.VALUE}\n"
            "    try:\n"
            "        data = Path(payload['outside_secret']).read_text(encoding='utf-8')\n"
            "        results['read_outside'] = f'LEAKED:{data}'\n"
            "    except Exception as exc:\n"
            "        results['read_outside'] = f'BLOCKED:{type(exc).__name__}'\n"
            "    try:\n"
            "        data = Path(payload['ws_escape_link']).read_text(encoding='utf-8')\n"
            "        results['read_symlink_escape'] = f'LEAKED:{data}'\n"
            "    except Exception as exc:\n"
            "        results['read_symlink_escape'] = f'BLOCKED:{type(exc).__name__}'\n"
            "    try:\n"
            "        Path(payload['outside_write']).write_text('pwn', encoding='utf-8')\n"
            "        results['write_outside'] = 'ESCAPED'\n"
            "    except Exception as exc:\n"
            "        results['write_outside'] = f'BLOCKED:{type(exc).__name__}'\n"
            "    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    sock.settimeout(1.0)\n"
            "    try:\n"
            "        sock.connect(('1.1.1.1', 80))\n"
            "        results['net'] = 'ESCAPED'\n"
            "    except PermissionError:\n"
            "        results['net'] = 'BLOCKED:PermissionError'\n"
            "    except OSError as exc:\n"
            "        results['net'] = 'BLOCKED:OSError' if exc.errno in (errno.EPERM, errno.EACCES) else f'ERR:{exc.errno}'\n"
            "    finally:\n"
            "        sock.close()\n"
            "    try:\n"
            "        import forbidden_sibling\n"
            "        results['forbidden_import'] = 'ESCAPED'\n"
            "    except ImportError as exc:\n"
            "        results['forbidden_import'] = f'BLOCKED:{exc}'\n"
            "    try:\n"
            "        import ctypes\n"
            "        results['ctypes_import'] = 'ESCAPED'\n"
            "    except ImportError as exc:\n"
            "        results['ctypes_import'] = f'BLOCKED:{exc}'\n"
            "    try:\n"
            "        subprocess.Popen([sys.executable, '-c', 'pass'])\n"
            "        results['exec'] = 'ESCAPED'\n"
            "    except PermissionError as exc:\n"
            "        results['exec'] = f'BLOCKED:{exc}'\n"
            "    try:\n"
            "        sys.meta_path.clear()\n"
            "        import forbidden_sibling as _fs2\n"
            "        results['meta_tamper'] = 'ESCAPED'\n"
            "    except PermissionError as exc:\n"
            "        results['meta_tamper'] = f'BLOCKED:{exc}'\n"
            "    return results\n",
            encoding="utf-8",
        )
        spec = HermeticEntrypointSpec(
            tool_id="b3.sandbox_probe",
            module_path="sandbox_probe",
            callable_attr="probe",
            expected_module_file_sha256=_sha256_file(probe_file),
            module_file_path=probe_file,
            allowed_import_prefixes=("allowed_helper",),
        )
        res = self.runner.run(
            spec,
            {
                "outside_secret": str(outside_secret),
                "ws_escape_link": str(self.ws / "ws_escape_link.txt"),
                "outside_write": str(outside_write),
            },
            security_context=self.ctx,
        )

        if self._expect_linux_landlock_unavailable():
            self.assertIn(
                res.execution_status,
                (ExecutionStatus.SANDBOX_UNAVAILABLE, ExecutionStatus.PERMISSION_DENIED),
            )
            return

        self.assertTrue(res.passed, res.error or res.stderr)
        out = res.output
        self.assertEqual(out["allowed_helper"], 123)
        self.assertTrue(out["read_outside"].startswith("BLOCKED:"), out)
        self.assertTrue(out["read_symlink_escape"].startswith("BLOCKED:"), out)
        self.assertNotIn(canary, res.stdout)
        self.assertNotIn(canary, res.stderr)
        self.assertTrue(out["write_outside"].startswith("BLOCKED:"), out)
        self.assertFalse(outside_write.exists())
        self.assertTrue(out["net"].startswith("BLOCKED:"), out)
        self.assertTrue(out["forbidden_import"].startswith("BLOCKED:"), out)
        self.assertTrue(out["ctypes_import"].startswith("BLOCKED:"), out)
        self.assertTrue(out["exec"].startswith("BLOCKED:"), out)
        self.assertTrue(out["meta_tamper"].startswith("BLOCKED:"), out)

    def test_detached_setsid_grandchild_killed_on_timeout_and_fd_isolation(self) -> None:
        orphan_marker = self.ws / "orphan_grandchild_survived.txt"
        timeout_file = self.ws / "detached_timeout.py"
        timeout_file.write_text(
            "import subprocess\n"
            "import sys\n"
            "import time\n\n"
            "def spawn_orphan(payload):\n"
            "    marker_path = payload['marker']\n"
            "    inner = (\n"
            "        'import time, pathlib; '\n"
            "        'time.sleep(0.65); '\n"
            "        + f'pathlib.Path({marker_path!r}).write_text(\"SURVIVED\")'\n"
            "    )\n"
            "    subprocess.Popen([sys.executable, '-I', '-S', '-c', inner], start_new_session=True)\n"
            "    time.sleep(5.0)\n"
            "    return {'unexpected': True}\n",
            encoding="utf-8",
        )
        exec_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "fs.write", "process.exec"],
            network_allowed=False,
        )
        timeout_spec = HermeticEntrypointSpec(
            tool_id="b3.detached_timeout",
            module_path="detached_timeout",
            callable_attr="spawn_orphan",
            expected_module_file_sha256=_sha256_file(timeout_file),
            module_file_path=timeout_file,
            timeout_s=0.20,
        )
        res_to = self.runner.run(timeout_spec, {"marker": str(orphan_marker)}, security_context=exec_ctx)

        if self._expect_linux_landlock_unavailable():
            self.assertIn(
                res_to.execution_status,
                (ExecutionStatus.SANDBOX_UNAVAILABLE, ExecutionStatus.PERMISSION_DENIED),
            )
            return

        self.assertTrue(res_to.timed_out)
        self.assertEqual(res_to.execution_status, ExecutionStatus.FAIL)
        time.sleep(0.85)
        self.assertFalse(orphan_marker.exists(), "Detached setsid() grandchild survived timeout!")

        # Inherited host FD + redirected stdio isolation check
        outside_fd_file = self.root / "outside_inherited_fd.txt"
        outside_fd_file.write_text("", encoding="utf-8")
        outside_stdout_file = self.root / "outside_stdout.txt"
        outside_stderr_file = self.root / "outside_stderr.txt"

        ext_fd = os.open(str(outside_fd_file), os.O_WRONLY | os.O_APPEND)
        fd_probe_file = self.ws / "fd_probe.py"
        fd_probe_file.write_text(
            "import os\n"
            "import sys\n\n"
            "def probe(payload):\n"
            "    ext_fd = int(payload['ext_fd'])\n"
            "    try:\n"
            "        os.write(ext_fd, b'ESCAPED_FD')\n"
            "        ext_blocked = False\n"
            "    except OSError:\n"
            "        ext_blocked = True\n"
            "    print('CAPTURED_STDOUT')\n"
            "    sys.stderr.write('CAPTURED_STDERR\\n')\n"
            "    return {'ext_blocked': ext_blocked}\n",
            encoding="utf-8",
        )
        fd_spec = HermeticEntrypointSpec(
            tool_id="b3.fd_probe",
            module_path="fd_probe",
            callable_attr="probe",
            expected_module_file_sha256=_sha256_file(fd_probe_file),
            module_file_path=fd_probe_file,
        )

        saved_1 = os.dup(1)
        saved_2 = os.dup(2)
        out_fd = os.open(str(outside_stdout_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        err_fd = os.open(str(outside_stderr_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.dup2(out_fd, 1)
            os.dup2(err_fd, 2)
            os.close(out_fd)
            os.close(err_fd)
            res_fd = self.runner.run(fd_spec, {"ext_fd": ext_fd}, security_context=self.ctx)
        finally:
            os.dup2(saved_1, 1)
            os.dup2(saved_2, 2)
            os.close(saved_1)
            os.close(saved_2)
            os.close(ext_fd)

        self.assertTrue(res_fd.passed, res_fd.error or res_fd.stderr)
        self.assertTrue(res_fd.output["ext_blocked"])
        self.assertEqual(outside_fd_file.read_text(encoding="utf-8"), "")
        self.assertEqual(outside_stdout_file.read_text(encoding="utf-8"), "")
        self.assertEqual(outside_stderr_file.read_text(encoding="utf-8"), "")
        self.assertIn("CAPTURED_STDOUT", res_fd.stdout)
        self.assertIn("CAPTURED_STDERR", res_fd.stderr)
        self.assertTrue(callable(_sanitize_worker_fds))

    def test_spec_validation_and_non_json_or_oversized_output_fail_closed(self) -> None:
        for bad_mod in ("", "a..b", "../evil", "pkg.__import__", "def", "a/b"):
            with self.assertRaises(ValueError, msg=bad_mod):
                HermeticEntrypointSpec(
                    tool_id="b3.invalid_mod",
                    module_path=bad_mod,
                    callable_attr="run",
                    expected_module_file_sha256="sha256:" + "a" * 64,
                )
        for bad_attr in ("", "a.b", "__import__", "1bad", "return"):
            with self.assertRaises(ValueError, msg=bad_attr):
                HermeticEntrypointSpec(
                    tool_id="b3.invalid_attr",
                    module_path="clean_mod",
                    callable_attr=bad_attr,
                    expected_module_file_sha256="sha256:" + "a" * 64,
                )

        # Oversized JSON response fails closed cleanly inside worker
        big_file = self.ws / "big_mod.py"
        big_file.write_text(
            "def run(_p):\n"
            "    return {'blob': 'A' * 50000}\n",
            encoding="utf-8",
        )
        big_spec = HermeticEntrypointSpec(
            tool_id="b3.big_out",
            module_path="big_mod",
            callable_attr="run",
            expected_module_file_sha256=_sha256_file(big_file),
            module_file_path=big_file,
            max_output_bytes=4096,
        )
        res_big = self.runner.run(big_spec, {}, security_context=self.ctx)
        if not self._expect_linux_landlock_unavailable():
            self.assertEqual(res_big.execution_status, ExecutionStatus.FAIL)
            self.assertIn("IPC_FRAME_TOO_LARGE", res_big.error)

        # Non-JSON return value fails closed cleanly inside worker
        bad_json_file = self.ws / "bad_json_mod.py"
        bad_json_file.write_text(
            "def run(_p):\n"
            "    return {1, 2, 3}\n",
            encoding="utf-8",
        )
        bad_json_spec = HermeticEntrypointSpec(
            tool_id="b3.bad_json",
            module_path="bad_json_mod",
            callable_attr="run",
            expected_module_file_sha256=_sha256_file(bad_json_file),
            module_file_path=bad_json_file,
        )
        res_bad_json = self.runner.run(bad_json_spec, {}, security_context=self.ctx)
        if not self._expect_linux_landlock_unavailable():
            self.assertEqual(res_bad_json.execution_status, ExecutionStatus.FAIL)
            self.assertIn("WORKER_OUTPUT_SERIALIZATION_FAILED", res_bad_json.error)

    def test_posix_path_raw_paths_parts_and_fspath_hooks_blocked_without_canary(self) -> None:
        canary = self.root / "posix_path_hook_canary.txt"
        tool_file = self.ws / "hook_safe_mod.py"
        tool_file.write_text("def run(_p): return {'ok': True}\n", encoding="utf-8")
        tool_sha = _sha256_file(tool_file)

        class _EvilFspathTrap:
            def __fspath__(self) -> str:
                canary.write_text("PWNED_FSPATH", encoding="utf-8")
                return str(tool_file)

            def __str__(self) -> str:
                canary.write_text("PWNED_STR", encoding="utf-8")
                return str(tool_file)

            def __repr__(self) -> str:
                canary.write_text("PWNED_REPR", encoding="utf-8")
                return "EVIL"

        class _EvilStrSub(str):
            def __fspath__(self) -> str:
                canary.write_text("PWNED_STRSUB_FSPATH", encoding="utf-8")
                return str(self)

            def __str__(self) -> str:
                canary.write_text("PWNED_STRSUB_STR", encoding="utf-8")
                return str.__str__(self)

            def strip(self, *args: Any, **kwargs: Any) -> str:
                canary.write_text("PWNED_STRSUB_STRIP", encoding="utf-8")
                return str.strip(self, *args, **kwargs)

        class _EvilPosixSub(PosixPath):
            def __fspath__(self) -> str:
                canary.write_text("PWNED_SUB_FSPATH", encoding="utf-8")
                return str(tool_file)

            def __str__(self) -> str:
                canary.write_text("PWNED_SUB_STR", encoding="utf-8")
                return str(tool_file)

        # 1. Even if PosixPath.__fspath__ / __str__ are hooked on the class, spec & runner root extraction must not fire them.
        def _bomb_fspath(self_p: Any) -> str:
            canary.write_text("PWNED_CLASS_FSPATH", encoding="utf-8")
            return "/pwned"

        def _bomb_str(self_p: Any) -> str:
            canary.write_text("PWNED_CLASS_STR", encoding="utf-8")
            return "/pwned"

        with unittest.mock.patch.object(PosixPath, "__fspath__", _bomb_fspath), unittest.mock.patch.object(
            PosixPath, "__str__", _bomb_str
        ):
            spec = HermeticEntrypointSpec(
                tool_id="b3.hook_free_path",
                module_path="hook_safe_mod",
                callable_attr="run",
                expected_module_file_sha256=tool_sha,
                module_file_path=tool_file,
            )
            _ = HermeticSpawnRunner(allowed_roots=[self.ws])
        self.assertEqual(spec.module_file_path, str(tool_file))
        self.assertFalse(canary.exists(), "Class-level PosixPath.__fspath__/__str__ hook fired!")

        # 2. Subclass PosixPath rejected without firing hooks.
        evil_sub = _EvilPosixSub(tool_file)
        with self.assertRaises(ValueError):
            HermeticEntrypointSpec(
                tool_id="b3.evil_sub",
                module_path="hook_safe_mod",
                callable_attr="run",
                expected_module_file_sha256=tool_sha,
                module_file_path=evil_sub,
            )
        with self.assertRaises(ValueError):
            HermeticSpawnRunner(allowed_roots=[evil_sub])
        self.assertFalse(canary.exists(), "PosixPath subclass hook fired!")

        # 3. Poisoned `_parts` / `_raw_paths` / `_str` slots on real PosixPath rejected without firing hooks.
        probe_path = self.ws / "hook_safe_mod.py"
        if hasattr(probe_path, "_raw_paths"):
            p_raw_bad = self.ws / "hook_safe_mod.py"
            object.__setattr__(p_raw_bad, "_raw_paths", [_EvilFspathTrap()])
            p_raw_str_bad = self.ws / "hook_safe_mod.py"
            object.__setattr__(p_raw_str_bad, "_str", _EvilFspathTrap())
            poisoned_real = [p_raw_bad, p_raw_str_bad]
        else:
            p_parts_bad = self.ws / "hook_safe_mod.py"
            object.__setattr__(p_parts_bad, "_parts", ["/", _EvilFspathTrap()])
            p_parts_sub = self.ws / "hook_safe_mod.py"
            object.__setattr__(p_parts_sub, "_parts", ["/", _EvilStrSub("ws"), "hook_safe_mod.py"])
            p_str_bad = self.ws / "hook_safe_mod.py"
            object.__setattr__(p_str_bad, "_str", _EvilFspathTrap())
            p_str_mismatch = self.ws / "hook_safe_mod.py"
            object.__setattr__(p_str_mismatch, "_str", "/etc/passwd")
            poisoned_real = [p_parts_bad, p_parts_sub, p_str_bad, p_str_mismatch]

        for bad_p in poisoned_real:
            with self.assertRaises(ValueError):
                HermeticEntrypointSpec(
                    tool_id="b3.poisoned_path_slot",
                    module_path="hook_safe_mod",
                    callable_attr="run",
                    expected_module_file_sha256=tool_sha,
                    module_file_path=bad_p,
                )
            with self.assertRaises(ValueError):
                HermeticSpawnRunner(allowed_roots=[bad_p])
        self.assertFalse(canary.exists(), "Poisoned PosixPath slot hook fired!")

        # 4. Also exercise Python 3.12+/3.13+ `_raw_paths` + `__dict__` branch explicitly across all Python versions.
        class _FakePy312PosixPath:
            def __init__(self, raw_paths: Any, *, str_val: Any = None, tail_cached: Any = None) -> None:
                self._raw_paths = raw_paths
                if str_val is not None:
                    self._str = str_val
                if tail_cached is not None:
                    self._tail_cached = tail_cached

            def __fspath__(self) -> str:
                canary.write_text("PWNED_FAKE312_FSPATH", encoding="utf-8")
                return str(tool_file)

            def __str__(self) -> str:
                canary.write_text("PWNED_FAKE312_STR", encoding="utf-8")
                return str(tool_file)

        with unittest.mock.patch.object(hermetic_worker_mod, "PurePosixPath", _FakePy312PosixPath):
            clean_312 = _FakePy312PosixPath([str(tool_file)])
            spec_312 = HermeticEntrypointSpec(
                tool_id="b3.clean_312_raw_paths",
                module_path="hook_safe_mod",
                callable_attr="run",
                expected_module_file_sha256=tool_sha,
                module_file_path=clean_312,  # type: ignore[arg-type]
            )
            self.assertEqual(spec_312.module_file_path, str(tool_file))

            for bad_312 in (
                _FakePy312PosixPath([_EvilFspathTrap()]),
                _FakePy312PosixPath([str(tool_file)], str_val=_EvilFspathTrap()),
                _FakePy312PosixPath([str(tool_file)], str_val="/etc/passwd"),
                _FakePy312PosixPath([str(tool_file)], tail_cached=[_EvilFspathTrap()]),
            ):
                with self.assertRaises(ValueError):
                    HermeticEntrypointSpec(
                        tool_id="b3.poisoned_312_raw_paths",
                        module_path="hook_safe_mod",
                        callable_attr="run",
                        expected_module_file_sha256=tool_sha,
                        module_file_path=bad_312,  # type: ignore[arg-type]
                    )
                with self.assertRaises(ValueError):
                    HermeticSpawnRunner(allowed_roots=[bad_312])  # type: ignore[list-item]
        self.assertFalse(canary.exists(), "Simulated Py3.12+ _raw_paths __fspath__ hook fired!")

        # 5. python_executable must be None or exact str.
        for bad_py in ("", _EvilFspathTrap(), _EvilStrSub(sys.executable), tool_file):
            with self.assertRaises(ValueError):
                HermeticSpawnRunner(python_executable=bad_py)  # type: ignore[arg-type]
        self.assertFalse(canary.exists(), "python_executable dunder hook fired!")


if __name__ == "__main__":
    unittest.main()
