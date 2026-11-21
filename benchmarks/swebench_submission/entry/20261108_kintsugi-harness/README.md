# Kintsugi-Harness (`20261108_kintsugi-harness`) — Synthetic SWE-like Local Regression Suite

> **Evaluation Scope:** Self-contained **synthetic local Python regression suite** reproducing canonical issue shapes in isolated subprocesses. Not an official externally run SWE-bench Docker harness or leaderboard submission.

- **System**: [Kintsugi-Harness](https://github.com/tunguyen1993/kintsugi-harness) (`@KML/1` + Native Rust `kintsugi-rs` AST Grounding Gate + 5-Pillar Pareto Swarm)
- **Technical Report**: [TECHNICAL_REPORT.md](https://github.com/tunguyen1993/kintsugi-harness/blob/main/benchmarks/swebench_submission/TECHNICAL_REPORT.md)
- **Author**: Nguyen Duc Tu ([@tunguyen1993](https://github.com/tunguyen1993))
- **Artifacts (`all_preds.jsonl`, `logs/`, `trajs/`)**: `https://github.com/tunguyen1993/kintsugi-harness/tree/main/benchmarks/swebench_submission`

## Submission Checklist
- [x] `evaluation_scope`: `synthetic_swe_like_regression_suite_not_official_swebench_leaderboard`
- [x] Does not use SWE-bench test knowledge (`PASS_TO_PASS`, `FAIL_TO_PASS`) inside patch selection
- [x] Does not use external hints or web-browsing lookups

## Summary of Synthetic Canonical Fixture Cases (`8/8 Local Subprocess Vectors Pass`)
| Instance ID | Reference Repo | Local Synthetic Status | Trajectory |
| :--- | :--- | :---: | :--- |
| `astropy__astropy-14995` | `astropy/astropy` | ✅ `SYNTHETIC_LOCAL_PASS` | [`trajs/astropy__astropy-14995.json`](../../trajs/astropy__astropy-14995.json) |
| `psf__requests-2317` | `psf/requests` | ✅ `SYNTHETIC_LOCAL_PASS` | [`trajs/psf__requests-2317.json`](../../trajs/psf__requests-2317.json) |
| `pytest-dev__pytest-5692` | `pytest-dev/pytest` | ✅ `SYNTHETIC_LOCAL_PASS` | [`trajs/pytest-dev__pytest-5692.json`](../../trajs/pytest-dev__pytest-5692.json) |
| `pallets__flask-4045` | `pallets/flask` | ✅ `SYNTHETIC_LOCAL_PASS` | [`trajs/pallets__flask-4045.json`](../../trajs/pallets__flask-4045.json) |
| `django__django-11999` | `django/django` | ✅ `SYNTHETIC_LOCAL_PASS` | [`trajs/django__django-11999.json`](../../trajs/django__django-11999.json) |
| `sympy__sympy-14024` | `sympy/sympy` | ✅ `SYNTHETIC_LOCAL_PASS` | [`trajs/sympy__sympy-14024.json`](../../trajs/sympy__sympy-14024.json) |
| `scikit-learn__scikit-learn-13241` | `scikit-learn/scikit-learn` | ✅ `SYNTHETIC_LOCAL_PASS` | [`trajs/scikit-learn__scikit-learn-13241.json`](../../trajs/scikit-learn__scikit-learn-13241.json) |
| `sphinx-doc__sphinx-8282` | `sphinx-doc/sphinx` | ✅ `SYNTHETIC_LOCAL_PASS` | [`trajs/sphinx-doc__sphinx-8282.json`](../../trajs/sphinx-doc__sphinx-8282.json) |
