# Linux systemd Scheduled Tasks Default

## Background

`make install TARGET=linux-systemd` installs both the main `tukuyomi.service`
unit and the scheduled-task timer unit, but the timer is not enabled unless the
operator passes `INSTALL_ENABLE_SCHEDULED_TASKS=1`.

This makes the default Linux host install less complete than the Admin UI
surface: scheduled tasks can be configured, but they do not execute until the
operator discovers and enables the timer separately.

## Decision

Enable the scheduled-task systemd timer by default for the `linux-systemd`
install path.

Operators can opt out explicitly:

```bash
make install TARGET=linux-systemd INSTALL_ENABLE_SCHEDULED_TASKS=0
```

The scheduled-task runner remains a systemd timer invoking the existing
oneshot command:

```bash
tukuyomi run-scheduled-tasks
```

## Scope

- Change `make install TARGET=linux-systemd` default behavior to enable and
  start `tukuyomi-scheduled-tasks.timer` when systemd install/start is enabled.
- Keep `INSTALL_ENABLE_SCHEDULED_TASKS=0` as the opt-out.
- Update English and Japanese README quick start guidance.
- Update English and Japanese binary deployment guidance.
- Do not change container/preview scheduler ownership.
- Do not move scheduler execution into the main `tukuyomi.service` process.

## Safety

- The timer runs once per minute and exits after due tasks are evaluated.
- Existing task-level locks and last-schedule-minute checks still prevent
  duplicate execution for the same task minute.
- Operators that do not want scheduled-task execution can disable it at install
  time with `INSTALL_ENABLE_SCHEDULED_TASKS=0` or disable the timer later with
  systemd.

## Acceptance

- `make install TARGET=linux-systemd` enables scheduled tasks by default.
- `make install TARGET=linux-systemd INSTALL_ENABLE_SCHEDULED_TASKS=0` leaves
  the timer disabled.
- `scripts/install_tukuyomi.sh` behaves consistently when invoked directly.
- README and binary deployment docs describe the new default and opt-out.
