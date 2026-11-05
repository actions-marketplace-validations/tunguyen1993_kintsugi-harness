# CLAUDE.md

<!-- KINTSUGI:START -->
<!-- KINTSUGI:KMI/1 START -->
# KMI/1;pack=core@0.5.0;rules=16;sha256=9601eb6a;jit=pre-tool-use
@CRIT: KS-001(secret!=literal->os.environ) | KS-002(sh!no_force_push_or_rm_rf) | KS-006(no_eval_exec_pickle->literal_eval) | KS-007(sql!fstring->param_query) | KS-012(prompt!no_system_override_injection) | KS-014(tls!rejectUnauthorized=true)
@HIGH: KS-003(subprocess!shell=True->argv_list) | KS-005(py!bare_except_pass->log_raise) | KS-008(http!no_timeout->timeout=10) | KS-011(crypto!random->secrets) | KS-013(js!exec_interp->execFile) | KS-015(cors!no_wildcard_with_credentials) | KS-016(go!http_client_timeout)
@MED : KS-004(py!mutable_default->None) | KS-009(no_todo_placeholder_stub) | KS-010(browser!launch->close_in_finally)
<!-- KINTSUGI:KMI/1 END -->
<!-- KINTSUGI:END -->
