# Scheduled Task Runtime Data Layout

`data/scheduled-tasks/` keeps generated runtime state for `/scheduled-tasks`.

- `state.json`
  - last-run status snapshots
- `locks/`
  - per-task execution locks
- `logs/`
  - per-task stdout/stderr logs

Task definitions live in `data/conf/scheduled-tasks.json` in the repository and
become `conf/scheduled-tasks.json` in binary or container deployments.

Only this `README.md` is intended to ship in generic release bundles. Generated
runtime state stays local to the deployment.
