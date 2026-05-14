import assert from "node:assert/strict";
import test from "node:test";
import {
  parseRuntimeAppsResponse,
  runtimeAppsToRaw,
  type RuntimeAppEntry,
} from "./runtimeAppsEditor.js";

function parseRaw(vhosts: ReturnType<typeof parseRuntimeAppsResponse>) {
  return JSON.parse(runtimeAppsToRaw(vhosts)) as { vhosts: RuntimeAppEntry[] };
}

test("Runtime Apps editor preserves PHP-FPM pool settings", () => {
  const poolSettings =
    "pm.max_children = 8\nrequest_slowlog_timeout = 3s\nrequest_slowlog_trace_depth = 40";
  const vhosts = parseRuntimeAppsResponse({
    runtime_apps: {
      vhosts: [
        {
          name: "shop",
          mode: "php-fpm",
          hostname: "127.0.0.1",
          listen_port: 9401,
          document_root: "apps/shop/public",
          runtime_id: "php82",
          php_fpm_pool_settings: poolSettings,
        },
      ],
    },
  });

  assert.equal(vhosts[0].phpPoolSettingsText, poolSettings);

  const raw = parseRaw(vhosts);
  assert.equal(raw.vhosts[0].php_fpm_pool_settings, poolSettings);
});

test("Runtime Apps editor omits pool settings outside PHP-FPM apps", () => {
  const vhosts = parseRuntimeAppsResponse({
    runtime_apps: {
      vhosts: [
        {
          name: "shop",
          mode: "php-fpm",
          hostname: "127.0.0.1",
          listen_port: 9401,
          document_root: "apps/shop/public",
          runtime_id: "php82",
        },
        {
          name: "mt",
          mode: "psgi",
          hostname: "127.0.0.1",
          listen_port: 9402,
          document_root: "apps/mt/public",
          runtime_id: "perl536",
          app_root: "apps/mt",
          psgi_file: "mt.psgi",
          php_fpm_pool_settings: "pm.max_children = 8",
        },
      ],
    },
  });

  const raw = parseRaw(vhosts);
  assert.equal(raw.vhosts[0].php_fpm_pool_settings, undefined);
  assert.equal(raw.vhosts[1].php_fpm_pool_settings, undefined);
});

test("Runtime Apps editor trims PHP-FPM pool settings before serializing", () => {
  const vhosts = parseRuntimeAppsResponse({
    runtime_apps: {
      vhosts: [
        {
          name: "shop",
          mode: "php-fpm",
          hostname: "127.0.0.1",
          listen_port: 9401,
          document_root: "apps/shop/public",
          runtime_id: "php82",
        },
      ],
    },
  });

  vhosts[0].phpPoolSettingsText = "\npm.max_children = 8\n";

  const raw = parseRaw(vhosts);
  assert.equal(raw.vhosts[0].php_fpm_pool_settings, "pm.max_children = 8");
});
