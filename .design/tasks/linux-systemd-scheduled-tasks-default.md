# Linux systemd Scheduled Tasks Default Tasks

Source plan: `.design/plans/linux-systemd-scheduled-tasks-default.md`

## Tasks

- [x] Change Makefile default `INSTALL_ENABLE_SCHEDULED_TASKS` to enabled.
- [x] Change `scripts/install_tukuyomi.sh` fallback default to enabled.
- [x] Update Makefile help to document `INSTALL_ENABLE_SCHEDULED_TASKS=0` as the opt-out.
- [x] Update `README.md` and `README.ja.md` quick start install text.
- [x] Update `docs/build/binary-deployment.md` and `.ja.md`.
- [x] Validate with whitespace checks and installer dry-run coverage.

## Acceptance

- Default Linux systemd install starts the scheduled-task timer.
- Operators can opt out with `INSTALL_ENABLE_SCHEDULED_TASKS=0`.
- English and Japanese docs are aligned.
