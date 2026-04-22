import assert from "node:assert/strict";
import test, { afterEach } from "node:test";
import {
    APIUnauthorizedError,
    AUTH_REQUIRED_EVENT,
    apiGetBinary,
    apiGetJson,
    apiPostJson,
    apiPutJson,
    getOperatorIdentity,
    setOperatorIdentity,
} from "./api.js";

const originalFetch = globalThis.fetch;
const originalWindow = globalThis.window;
const originalDocument = globalThis.document;
const originalDispatchEvent = globalThis.dispatchEvent;

afterEach(() => {
    globalThis.fetch = originalFetch;
    globalThis.window = originalWindow;
    globalThis.document = originalDocument;
    globalThis.dispatchEvent = originalDispatchEvent;
    setOperatorIdentity("");
});

test("apiGetJson uses default API base path", async () => {
    let requestedUrl = "";
    globalThis.fetch = async (input) => {
        requestedUrl = String(input);
        return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    };

    const out = await apiGetJson<{ ok: boolean }>("/status");
    assert.equal(out.ok, true);
    assert.equal(requestedUrl, "/tukuyomi-api/status");
});

test("apiGetJson surfaces API error payload", async () => {
    globalThis.fetch = async () => {
        return new Response(JSON.stringify({ error: "denied" }), {
            status: 403,
            headers: { "Content-Type": "application/json" },
        });
    };

    await assert.rejects(() => apiGetJson("/status"), /denied/);
});

test("apiPutJson sends JSON body and content type", async () => {
    let method = "";
    let contentType = "";
    let body = "";
    let csrfHeader = "";
    globalThis.fetch = async (_input, init) => {
        method = String(init?.method || "");
        const headers = new Headers(init?.headers);
        contentType = headers.get("Content-Type") || "";
        csrfHeader = headers.get("X-CSRF-Token") || "";
        body = String(init?.body || "");
        return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    };
    globalThis.document = { cookie: "tukuyomi_admin_csrf=csrf-token-123" } as Document;

    await apiPutJson("/rules", { a: 1 });
    assert.equal(method, "PUT");
    assert.equal(contentType, "application/json");
    assert.equal(csrfHeader, "csrf-token-123");
    assert.equal(body, JSON.stringify({ a: 1 }));
});

test("operator identity persists through localStorage helpers", () => {
    const storage = new Map<string, string>();
    globalThis.window = {
        localStorage: {
            getItem: (key: string) => storage.get(key) ?? null,
            setItem: (key: string, value: string) => {
                storage.set(key, value);
            },
            removeItem: (key: string) => {
                storage.delete(key);
            },
        },
    } as Window & typeof globalThis;

    setOperatorIdentity("alice@example.com");
    assert.equal(getOperatorIdentity(), "alice@example.com");
    assert.equal(storage.get("tukuyomi_operator_identity"), "alice@example.com");

    setOperatorIdentity("");
    assert.equal(getOperatorIdentity(), "");
    assert.equal(storage.has("tukuyomi_operator_identity"), false);
});

test("apiGetJson attaches X-Tukuyomi-Actor when configured", async () => {
    let sentActor = "";
    globalThis.fetch = async (_input, init) => {
        sentActor = new Headers(init?.headers).get("X-Tukuyomi-Actor") || "";
        return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    };
    setOperatorIdentity("alice@example.com");

    const out = await apiGetJson<{ ok: boolean }>("/status");
    assert.equal(out.ok, true);
    assert.equal(sentActor, "alice@example.com");
});

test("apiGetJson omits X-Tukuyomi-Actor when operator identity is empty", async () => {
    let sentActor: string | null = "placeholder";
    setOperatorIdentity("");
    globalThis.fetch = async (_input, init) => {
        const headers = new Headers(init?.headers);
        sentActor = headers.get("X-Tukuyomi-Actor");
        return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    };

    const out = await apiGetJson<{ ok: boolean }>("/status");
    assert.equal(out.ok, true);
    assert.equal(sentActor, null);
});

test("apiGetJson emits auth required and raises APIUnauthorizedError on 401", async () => {
    const seen: string[] = [];
    globalThis.dispatchEvent = ((event: Event) => {
        seen.push(event.type);
        return true;
    }) as typeof globalThis.dispatchEvent;
    globalThis.fetch = async () =>
        new Response(JSON.stringify({ error: "Unauthorized" }), {
            status: 401,
            headers: { "Content-Type": "application/json" },
        });

    await assert.rejects(() => apiGetJson("/status"), APIUnauthorizedError);
    assert.deepEqual(seen, [AUTH_REQUIRED_EVENT]);
});

test("apiPostJson attaches CSRF token from cookie", async () => {
    let csrfHeader = "";
    globalThis.document = { cookie: "foo=bar; tukuyomi_admin_csrf=csrf-cookie-token" } as Document;
    globalThis.fetch = async (_input, init) => {
        csrfHeader = new Headers(init?.headers).get("X-CSRF-Token") || "";
        return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    };

    const out = await apiPostJson<{ ok: boolean }>("/auth/logout", {});
    assert.equal(out.ok, true);
    assert.equal(csrfHeader, "csrf-cookie-token");
});

test("apiGetBinary decodes RFC5987 filename", async () => {
    globalThis.fetch = async () => {
        return new Response(new Blob(["hello"]), {
            status: 200,
            headers: {
                "Content-Type": "application/gzip",
                "Content-Disposition": "attachment; filename*=UTF-8''waf%20events.ndjson.gz",
            },
        });
    };

    const out = await apiGetBinary("/logs/download?src=waf");
    assert.equal(out.contentType, "application/gzip");
    assert.equal(out.filename, "waf events.ndjson.gz");
    assert.equal(out.blob.size, 5);
});
