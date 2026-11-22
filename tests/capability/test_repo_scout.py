"""Tests for `kintsugi.tools.repo_scout.RepoScout` (`KINTSUGI-NEXTGEN/1` Section H1)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from kintsugi.tools.repo_scout import REPO_INDEX_SCHEMA, RepoScout


def _write_text(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _build_sample_python_repo(root: Path) -> None:
    _write_text(root / "src" / "app" / "__init__.py", "from .leaf import leaf_fn\n")
    _write_text(
        root / "src" / "app" / "leaf.py",
        (
            "def leaf_fn(value: int) -> int:\n"
            "    return value + 1\n\n"
            "class LeafHelper:\n"
            "    def compute(self, x: int) -> int:\n"
            "        return leaf_fn(x)\n"
        ),
    )
    _write_text(
        root / "src" / "app" / "middle.py",
        (
            "from .leaf import LeafHelper, leaf_fn\n\n"
            "def run_middle(n: int) -> int:\n"
            "    helper = LeafHelper()\n"
            "    return helper.compute(n) + leaf_fn(n)\n"
        ),
    )
    _write_text(
        root / "src" / "app" / "obsolete.py",
        "def old_unused() -> str:\n    return 'bye'\n",
    )
    _write_text(
        root / "src" / "app" / "unrelated.py",
        "def solo_fn() -> int:\n    return 42\n",
    )
    _write_text(
        root / "tests" / "test_leaf.py",
        (
            "from app.leaf import leaf_fn\n\n"
            "def test_leaf_basic():\n"
            "    assert leaf_fn(1) == 2\n"
        ),
    )
    _write_text(
        root / "tests" / "test_middle.py",
        (
            "from app.middle import run_middle\n\n"
            "def test_middle_flow():\n"
            "    assert run_middle(2) == 6\n"
        ),
    )
    _write_text(
        root / "tests" / "test_pkg_init.py",
        (
            "from app import leaf_fn\n\n"
            "def test_reexport():\n"
            "    assert leaf_fn(5) == 6\n"
        ),
    )
    _write_text(
        root / "tests" / "test_unrelated.py",
        (
            "from app.unrelated import solo_fn\n\n"
            "def test_solo():\n"
            "    assert solo_fn() == 42\n"
        ),
    )


class TestRepoScout(unittest.TestCase):
    """Comprehensive unit, differential, and security tests for RepoScout."""

    def test_walker_excludes_noise_and_rejects_all_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as outer_tmp, tempfile.TemporaryDirectory() as repo_tmp:
            outside_dir = Path(outer_tmp)
            secret_py = _write_text(outside_dir / "outside_secret.py", "SECRET = 'nope'\n")
            _write_text(outside_dir / "nested" / "escape_mod.py", "def escape():\n    return 1\n")

            repo = Path(repo_tmp)
            _build_sample_python_repo(repo)

            # Excluded directories must be pruned even when they contain .py/.rs files
            for excluded in (".git", "__pycache__", "node_modules", "target", ".venv", ".kintsugi", "build", "dist"):
                _write_text(repo / excluded / "ignored.py", "def should_ignore():\n    pass\n")

            # Symlinks inside repo (file escape, directory escape, internal symlink)
            (repo / "src" / "app" / "escape_file.py").symlink_to(secret_py)
            (repo / "src" / "escape_dir").symlink_to(outside_dir / "nested")
            (repo / "src" / "app" / "internal_alias.py").symlink_to(repo / "src" / "app" / "leaf.py")

            scout = RepoScout(repo)
            walked = scout.walk_files()

            self.assertEqual(walked, sorted(walked))
            for bad in (
                "src/app/escape_file.py",
                "src/escape_dir/escape_mod.py",
                "src/app/internal_alias.py",
            ):
                self.assertNotIn(bad, walked)
            for excluded in (".git", "__pycache__", "node_modules", "target", ".venv", ".kintsugi", "build", "dist"):
                self.assertFalse(any(p.startswith(f"{excluded}/") for p in walked))

            # update_from_paths and map_changed_files_to_tests must also refuse symlinks and .. traversal
            scout.build()
            impact = scout.map_changed_files_to_tests([
                "src/app/escape_file.py",
                "src/escape_dir/escape_mod.py",
                "../../outside_secret.py",
                str(secret_py),
                "src/app/leaf.py",
            ])
            self.assertEqual(impact["changed_files"], ["src/app/leaf.py"])
            self.assertEqual(len(impact["rejected_paths"]), 4)

            # Symlinked repo root itself is refused
            sym_root = outside_dir / "sym_repo"
            sym_root.symlink_to(repo)
            with self.assertRaises(PermissionError):
                RepoScout(sym_root)

    def test_save_and_load_reject_symlink_index_and_tampered_paths(self) -> None:
        with tempfile.TemporaryDirectory() as outer_tmp, tempfile.TemporaryDirectory() as repo_tmp:
            outside = Path(outer_tmp)
            repo = Path(repo_tmp)
            _build_sample_python_repo(repo)

            scout = RepoScout(repo)
            scout.build()
            saved_path = scout.save()
            self.assertEqual(saved_path, repo.resolve() / ".kintsugi" / "repo_scout_index.json")
            self.assertTrue(saved_path.is_file())
            self.assertEqual(os.stat(saved_path).st_mode & 0o777, 0o600)

            # Symlinked index file must raise PermissionError on load and save
            evil_target = _write_text(outside / "evil.json", "{}")
            sym_index = repo / ".kintsugi" / "evil_index.json"
            sym_index.symlink_to(evil_target)
            with self.assertRaises(PermissionError):
                RepoScout(repo, index_path=sym_index)
            with self.assertRaises(PermissionError):
                scout.load(sym_index)

            # Symlinked .kintsugi directory must be rejected
            sym_dir = outside / "sym_kintsugi"
            sym_dir.symlink_to(outside)
            with self.assertRaises(PermissionError):
                RepoScout(repo, index_path=sym_dir / "repo_scout_index.json")

            # Tampered index containing .. traversal path must fail closed
            tampered = outside / "tampered.json"
            payload = json.loads(saved_path.read_text(encoding="utf-8"))
            payload["files"]["../escape.py"] = payload["files"]["src/app/leaf.py"]
            tampered.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ValueError):
                scout.load(tampered)

    def test_differential_incremental_update_matches_cold_build_exact(self) -> None:
        with tempfile.TemporaryDirectory() as repo_tmp:
            repo = Path(repo_tmp)
            _build_sample_python_repo(repo)

            # Session 1: Cold build + persist
            scout_init = RepoScout(repo)
            idx_init = scout_init.build()
            self.assertEqual(idx_init["schema"], REPO_INDEX_SCHEMA)
            self.assertEqual(scout_init.last_stats["parsed_files"], 9)
            scout_init.save()

            # Session 2: Unchanged reload + update parses 0 files
            scout_noop = RepoScout(repo)
            scout_noop.load()
            idx_noop = scout_noop.update()
            self.assertEqual(scout_noop.last_stats["parsed_files"], 0)
            self.assertEqual(scout_noop.last_stats["skipped_stat_hits"], 9)
            self.assertEqual(idx_noop["index_digest"], idx_init["index_digest"])

            # Mutate repo: modify leaf.py, add feature.py + test_feature.py, delete obsolete.py
            _write_text(
                repo / "src" / "app" / "leaf.py",
                (
                    "def leaf_fn(value: int) -> int:\n"
                    "    return value + 10\n\n"
                    "def leaf_bonus(x: int) -> int:\n"
                    "    return leaf_fn(x) * 2\n\n"
                    "class LeafHelper:\n"
                    "    def compute(self, x: int) -> int:\n"
                    "        return leaf_bonus(x)\n"
                ),
            )
            _write_text(
                repo / "src" / "app" / "feature.py",
                "from .leaf import leaf_bonus\n\ndef feature_entry(v: int) -> int:\n    return leaf_bonus(v)\n",
            )
            _write_text(
                repo / "tests" / "test_feature.py",
                "from app.feature import feature_entry\n\ndef test_feature():\n    assert feature_entry(1) == 22\n",
            )
            (repo / "src" / "app" / "obsolete.py").unlink()

            # Touch unrelated.py (mtime changes, bytes unchanged) -> update() catches hash hit without re-parse
            unrelated_path = repo / "src" / "app" / "unrelated.py"
            old_stat = os.stat(unrelated_path)
            os.utime(unrelated_path, ns=(old_stat.st_atime_ns + 1_000_000, old_stat.st_mtime_ns + 1_000_000))

            # Incremental full-walk update()
            scout_inc = RepoScout(repo)
            scout_inc.load()
            idx_inc = scout_inc.update()
            inc_stats = scout_inc.last_stats
            self.assertEqual(inc_stats["added_files"], 2)
            self.assertEqual(inc_stats["modified_files"], 1)
            self.assertEqual(inc_stats["deleted_files"], 1)
            self.assertEqual(inc_stats["parsed_files"], 3)
            self.assertEqual(inc_stats["reused_files"], 7)
            self.assertEqual(inc_stats["skipped_stat_hits"], 6)
            self.assertEqual(inc_stats["skipped_hash_hits"], 1)

            # Incremental explicit update_from_paths() from previous saved snapshot (mix of ./, abs, and rel)
            scout_diff = RepoScout(repo)
            scout_diff.load()
            idx_diff = scout_diff.update_from_paths([
                "./src/app/leaf.py",
                repo / "src" / "app" / "feature.py",
                "tests/test_feature.py",
                "src/app/obsolete.py",
            ])
            self.assertEqual(scout_diff.last_stats["parsed_files"], 3)
            self.assertEqual(scout_diff.last_stats["deleted_files"], 1)

            # Fresh cold build() on final repo state
            scout_cold = RepoScout(repo)
            idx_cold = scout_cold.build()

            # Differential parity assertions across update(), update_from_paths(), and cold build()
            self.assertEqual(idx_inc["index_digest"], idx_cold["index_digest"])
            self.assertEqual(idx_diff["index_digest"], idx_cold["index_digest"])
            self.assertEqual(idx_inc["manifest_sha"], idx_cold["manifest_sha"])
            self.assertEqual(idx_diff["manifest_sha"], idx_cold["manifest_sha"])
            self.assertEqual(idx_inc["dependencies"], idx_cold["dependencies"])
            self.assertEqual(idx_diff["dependencies"], idx_cold["dependencies"])
            self.assertEqual(idx_inc["reverse_dependencies"], idx_cold["reverse_dependencies"])
            self.assertEqual(idx_diff["reverse_dependencies"], idx_cold["reverse_dependencies"])
            self.assertEqual(idx_inc["test_files"], idx_cold["test_files"])
            self.assertEqual(idx_diff["test_files"], idx_cold["test_files"])
            self.assertEqual(idx_inc["symbol_index"], idx_cold["symbol_index"])
            self.assertEqual(idx_diff["symbol_index"], idx_cold["symbol_index"])

    def test_ast_extraction_call_sites_and_impact_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as repo_tmp:
            repo = Path(repo_tmp)
            _build_sample_python_repo(repo)
            _write_text(repo / "src" / "app" / "broken_syntax.py", "def broken(:\n    pass\n")

            scout = RepoScout(repo, include_ast_hashes=True)
            idx = scout.build()

            self.assertTrue(idx["files"]["src/app/broken_syntax.py"]["syntax_error"])
            leaf_syms = scout.find_symbol("LeafHelper.compute")
            self.assertEqual(len(leaf_syms), 1)
            self.assertEqual(leaf_syms[0]["file"], "src/app/leaf.py")
            self.assertEqual(leaf_syms[0]["start_line"], 5)
            self.assertEqual(leaf_syms[0]["end_line"], 6)

            # Alpha-normalized AST quotient hash compatibility
            h_leaf = scout.compute_symbol_ast_hash("src/app/leaf.py", "leaf_fn")
            self.assertIsNotNone(h_leaf)
            self.assertEqual(len(h_leaf or ""), 16)

            # Call-site discovery across modules & tests
            calls = scout.find_call_sites(["leaf_fn"])
            call_files = {c["file"] for c in calls}
            self.assertEqual(call_files, {"src/app/leaf.py", "src/app/middle.py", "tests/test_leaf.py", "tests/test_pkg_init.py"})

            # Diff-to-Test Impact Mapping for src/app/leaf.py
            impact = scout.map_changed_files_to_tests(["src/app/leaf.py"])
            rec = impact["recommended_tests"]
            self.assertIn("tests/test_leaf.py", rec)
            self.assertIn("tests/test_middle.py", rec)
            self.assertIn("tests/test_pkg_init.py", rec)
            self.assertNotIn("tests/test_unrelated.py", rec)

            # Direct test importing & calling changed symbol ranks ahead of transitive hop
            self.assertEqual(rec[0], "tests/test_leaf.py")
            by_path = {t["path"]: t for t in impact["test_targets"]}
            self.assertEqual(by_path["tests/test_leaf.py"]["distance"], 1)
            self.assertEqual(by_path["tests/test_middle.py"]["distance"], 2)
            self.assertEqual(
                by_path["tests/test_middle.py"]["via"],
                ["src/app/leaf.py", "src/app/middle.py", "tests/test_middle.py"],
            )
            self.assertIn("leaf_fn", by_path["tests/test_leaf.py"]["matched_symbols"])
            self.assertTrue(len(by_path["tests/test_leaf.py"]["call_sites"]) >= 1)

            # Direct modification to test file itself ranks at distance 0
            direct_test_impact = scout.map_changed_files_to_tests(["tests/test_unrelated.py"])
            self.assertEqual(direct_test_impact["recommended_tests"], ["tests/test_unrelated.py"])
            self.assertEqual(direct_test_impact["test_targets"][0]["distance"], 0)

    def test_rust_symbol_extraction_and_impact_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as repo_tmp:
            repo = Path(repo_tmp)
            _write_text(
                repo / "rust" / "src" / "engine.rs",
                (
                    "// pub fn fake_commented() {}\n"
                    "/* pub struct IgnoredBlock { x: i32 } */\n"
                    "pub struct EngineState {\n"
                    "    pub count: usize,\n"
                    "}\n\n"
                    "pub fn run_engine(val: usize) -> usize {\n"
                    '    let note = r#"pub fn fake_in_raw_str() {}"#;\n'
                    "    let _ = note.len();\n"
                    "    val + 1\n"
                    "}\n"
                ),
            )
            _write_text(
                repo / "rust" / "src" / "lib.rs",
                (
                    "pub mod engine;\n"
                    "pub use crate::engine::{EngineState, run_engine};\n\n"
                    "pub fn api_entry(v: usize) -> usize {\n"
                    "    engine::run_engine(v)\n"
                    "}\n"
                ),
            )
            _write_text(
                repo / "rust" / "tests" / "engine_integration.rs",
                (
                    "use kintsugi_demo::api_entry;\n\n"
                    "#[test]\n"
                    "fn test_api_entry_works() {\n"
                    "    assert_eq!(api_entry(4), 5);\n"
                    "}\n"
                ),
            )
            _write_text(
                repo / "rust" / "tests" / "other_integration.rs",
                (
                    "#[test]\n"
                    "fn test_standalone() {\n"
                    "    assert_eq!(2 + 2, 4);\n"
                    "}\n"
                ),
            )

            scout = RepoScout(repo)
            idx = scout.build()

            self.assertEqual(scout.find_symbol("fake_commented"), [])
            self.assertEqual(scout.find_symbol("IgnoredBlock"), [])
            self.assertEqual(scout.find_symbol("fake_in_raw_str"), [])

            eng_fn = scout.find_symbol("run_engine")
            self.assertEqual(len(eng_fn), 1)
            self.assertEqual(eng_fn[0]["kind"], "function")
            self.assertEqual(eng_fn[0]["visibility"], "public")
            self.assertEqual(eng_fn[0]["start_line"], 7)
            self.assertEqual(eng_fn[0]["end_line"], 11)

            eng_struct = scout.find_symbol("EngineState")
            self.assertEqual(len(eng_struct), 1)
            self.assertEqual(eng_struct[0]["kind"], "struct")
            self.assertEqual(eng_struct[0]["visibility"], "public")

            mod_syms = scout.find_symbol("engine")
            self.assertEqual(len(mod_syms), 1)
            self.assertEqual(mod_syms[0]["kind"], "mod")
            self.assertEqual(mod_syms[0]["visibility"], "public")

            self.assertIn("rust/src/engine.rs", idx["dependencies"]["rust/src/lib.rs"])
            self.assertIn("rust/src/lib.rs", idx["dependencies"]["rust/tests/engine_integration.rs"])

            impact = scout.map_changed_files_to_tests(["rust/src/engine.rs"])
            self.assertIn("rust/tests/engine_integration.rs", impact["recommended_tests"])
            self.assertNotIn("rust/tests/other_integration.rs", impact["recommended_tests"])

    def test_live_kintsugi_repo_smoke(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent.parent
        with tempfile.TemporaryDirectory() as cache_tmp:
            scout = RepoScout(repo_root, index_path=Path(cache_tmp) / "live_idx.json")
            idx1 = scout.build()
            scout.save()

            scout2 = RepoScout(repo_root, index_path=Path(cache_tmp) / "live_idx.json")
            scout2.load()
            idx2 = scout2.update()

            self.assertEqual(idx1["index_digest"], idx2["index_digest"])
            self.assertEqual(scout2.last_stats["parsed_files"], 0)
            impact = scout2.map_changed_files_to_tests(["src/kintsugi/shield.py"])
            self.assertIn("tests/test_kintsugi.py", impact["recommended_tests"])
            summary = scout2.to_grounding_summary()
            self.assertEqual(summary["schema"], REPO_INDEX_SCHEMA)
            self.assertGreater(summary["indexed_files"], 20)


if __name__ == "__main__":
    unittest.main()
