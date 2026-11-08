# Kintsugi-Harness v1.9.0 (`20261108_kintsugi-harness`)

- **System**: [Kintsugi-Harness](https://github.com/tunguyen1993/kintsugi-harness) (`@KML/1` + Native Rust `kintsugi-rs` AST Grounding Gate + 5-Pillar Pareto Swarm)
- **Technical Report**: [TECHNICAL_REPORT.md](https://github.com/tunguyen1993/kintsugi-harness/blob/main/benchmarks/swebench_submission/TECHNICAL_REPORT.md)
- **Author**: Nguyen Duc Tu ([@tunguyen1993](https://github.com/tunguyen1993))
- **Artifacts (`all_preds.jsonl`, `logs/`, `trajs/`)**: `https://github.com/tunguyen1993/kintsugi-harness/tree/main/benchmarks/swebench_submission`

## Submission Checklist
- [x] Is a `Best@k` (`attempts: 2+`) submission where a distinct neuro-symbolic AST & Pareto module selects the winning candidate without using `PASS_TO_PASS` or `FAIL_TO_PASS` test knowledge
- [x] Does not use SWE-bench test knowledge (`PASS_TO_PASS`, `FAIL_TO_PASS`)
- [x] Does not use the `hints` field in SWE-bench
- [x] Does not use web-browsing to look up SWE-bench solutions

## Summary of Verified Canonical Instances (`8/8 Resolved — 100.0%`)
| Instance ID | Repository | Status | Trajectory |
| :--- | :--- | :---: | :--- |
| `astropy__astropy-14995` | `astropy/astropy` | ✅ `RESOLVED` | [`trajs/astropy__astropy-14995.json`](../../trajs/astropy__astropy-14995.json) |
| `psf__requests-2317` | `psf/requests` | ✅ `RESOLVED` | [`trajs/psf__requests-2317.json`](../../trajs/psf__requests-2317.json) |
| `pytest-dev__pytest-5692` | `pytest-dev/pytest` | ✅ `RESOLVED` | [`trajs/pytest-dev__pytest-5692.json`](../../trajs/pytest-dev__pytest-5692.json) |
| `pallets__flask-4045` | `pallets/flask` | ✅ `RESOLVED` | [`trajs/pallets__flask-4045.json`](../../trajs/pallets__flask-4045.json) |
| `django__django-11999` | `django/django` | ✅ `RESOLVED` | [`trajs/django__django-11999.json`](../../trajs/django__django-11999.json) |
| `sympy__sympy-14024` | `sympy/sympy` | ✅ `RESOLVED` | [`trajs/sympy__sympy-14024.json`](../../trajs/sympy__sympy-14024.json) |
| `scikit-learn__scikit-learn-13241` | `scikit-learn/scikit-learn` | ✅ `RESOLVED` | [`trajs/scikit-learn__scikit-learn-13241.json`](../../trajs/scikit-learn__scikit-learn-13241.json) |
| `sphinx-doc__sphinx-8282` | `sphinx-doc/sphinx` | ✅ `RESOLVED` | [`trajs/sphinx-doc__sphinx-8282.json`](../../trajs/sphinx-doc__sphinx-8282.json) |
