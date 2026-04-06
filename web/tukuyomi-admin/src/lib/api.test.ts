import assert from "node:assert/strict";
import test, { afterEach } from "node:test";
import { AUTH_REQUIRED_EVENT, APIUnauthorizedError, apiGetBinary, apiGetJson, apiPutJson } from "./api.js";

const originalFetch = globalThis.fetch;
const originalDocument = globalThis.document;
const originalDispatchEvent = globalThis.dispatchEvent;

afterEach(() => {
    globalThis.fetch = originalFetch;
    globalThis.document = originalDocument;
    globalThis.dispatchEvent = originalDispatchEvent;
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
    globalThis.document = { cookie: "tukuyomi_admin_csrf=csrf-token-123" } as Document;
    globalThis.fetch = async (_input, init) => {
        method = String(init?.method || "");
        contentType = new Headers(init?.headers).get("Content-Type") || "";
        csrfHeader = new Headers(init?.headers).get("X-CSRF-Token") || "";
        body = String(init?.body || "");
        return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    };

    await apiPutJson("/rules", { a: 1 });
    assert.equal(method, "PUT");
    assert.equal(contentType, "application/json");
    assert.equal(csrfHeader, "csrf-token-123");
    assert.equal(body, JSON.stringify({ a: 1 }));
});

test("apiGetJson dispatches auth-required on 401", async () => {
    let eventType = "";
    globalThis.dispatchEvent = (event) => {
        eventType = event.type;
        return true;
    };
    globalThis.fetch = async () => {
        return new Response(JSON.stringify({ error: "invalid API key" }), {
            status: 401,
            headers: { "Content-Type": "application/json" },
        });
    };

    await assert.rejects(() => apiGetJson("/status"), APIUnauthorizedError);
    assert.equal(eventType, AUTH_REQUIRED_EVENT);
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
