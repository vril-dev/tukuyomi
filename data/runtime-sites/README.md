# Runtime Site Source Layout

`data/runtime-sites/` keeps operator-managed Runtime App source trees that may
be adopted by Center Runtime App Deploy.

- `<app-id>/`
  - application source tree selected for baseline adoption
- `<app-id>/public/`
  - common PHP-FPM document root inside an application source tree

Do not add a shared `samples/` layer here. Put each application directly under
`data/runtime-sites/<app-id>/`.

Runtime App Deploy only adopts source paths under `data/runtime-sites/`.
Use repository-relative paths in Runtime Apps definitions.
