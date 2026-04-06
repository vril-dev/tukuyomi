type EnvLike = {
    VITE_CORAZA_API_BASE?: string;
};

const env = ((import.meta as ImportMeta & { env?: EnvLike }).env ?? {});
const API_BASE = env.VITE_CORAZA_API_BASE || "/tukuyomi-api";
const CSRF_COOKIE_NAME = "tukuyomi_admin_csrf";

export const AUTH_REQUIRED_EVENT = "tukuyomi-admin-auth-required";

export class APIUnauthorizedError extends Error {
    constructor(message = "Unauthorized") {
        super(message);
        this.name = "APIUnauthorizedError";
    }
}

function readCookie(name: string) {
    if (typeof document === "undefined" || !document.cookie) {
        return "";
    }
    const prefix = `${name}=`;
    for (const part of document.cookie.split(";")) {
        const trimmed = part.trim();
        if (trimmed.startsWith(prefix)) {
            return decodeURIComponent(trimmed.slice(prefix.length));
        }
    }
    return "";
}

function isSafeMethod(method: string) {
    const normalized = method.toUpperCase();
    return normalized === "GET" || normalized === "HEAD" || normalized === "OPTIONS";
}

function withCSRF(headers: Headers, method: string) {
    if (isSafeMethod(method)) {
        return;
    }
    const token = readCookie(CSRF_COOKIE_NAME);
    if (token) {
        headers.set("X-CSRF-Token", token);
    }
}

function emitAuthRequired() {
    const target = globalThis as typeof globalThis & { dispatchEvent?: (event: Event) => boolean };
    if (typeof target.dispatchEvent !== "function") {
        return;
    }

    if (typeof CustomEvent === "function") {
        target.dispatchEvent(new CustomEvent(AUTH_REQUIRED_EVENT));
        return;
    }
    if (typeof Event === "function") {
        target.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));
    }
}

async function apiFetch(path: string, init: RequestInit = {}) {
    const method = String(init.method || "GET").toUpperCase();
    const headers = new Headers(init.headers || {});
    withCSRF(headers, method);

    const res = await fetch(`${API_BASE}${path}`, {
        ...init,
        method,
        headers,
        credentials: "include",
    });

    if (res.status === 401) {
        emitAuthRequired();
    }

    return res;
}

export async function apiGetText(path: string, init: RequestInit = {}) {
    const res = await apiFetch(path, init);

    if (! res.ok) {
        if (res.status === 401) {
            throw new APIUnauthorizedError();
        }
        throw new Error(`HTTP ${res.status}`);
    }

    return res.text();
}

export async function apiGetJson<T = any>(path: string, init: RequestInit = {}) {
    const res = await apiFetch(path, init);
    const data = await res.json().catch(() => ({}));

    if (! res.ok) {
        if (res.status === 401) {
            throw new APIUnauthorizedError((data as any)?.error || "Unauthorized");
        }
        throw new Error((data as any)?.error || `HTTP ${res.status}`);
    }

    return data as T;
}

export async function apiPostText(path: string, body: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers || {});
    headers.set("Content-Type", "text/plain");
    const res = await apiFetch(path, {
        method: "POST",
        body,
        ...init,
        headers,
    });

    if (! res.ok) {
        if (res.status === 401) {
            throw new APIUnauthorizedError();
        }
        throw new Error(`HTTP ${res.status}`);
    }

    return res;
}

export async function apiPostJson<T = any>(path: string, body: unknown, init: RequestInit = {}) {
    const headers = new Headers(init.headers || {});
    headers.set("Content-Type", "application/json");

    const res = await apiFetch(path, {
        method: "POST",
        body: JSON.stringify(body),
        ...init,
        headers,
    });

    const data = await res.json().catch(() => ({}));
    if (! res.ok) {
        if (res.status === 401) {
            throw new APIUnauthorizedError((data as any)?.error || "Unauthorized");
        }
        throw new Error((data as any)?.error || `HTTP ${res.status}`);
    }

    return data as T;
}

export async function apiPutJson<T = any>(path: string, body: unknown, init: RequestInit = {}) {
    const headers = new Headers(init.headers ||{});
    headers.set("Content-Type", "application/json");

    const res = await apiFetch(path, {
        method: "PUT",
        body: JSON.stringify(body),
        ...init,
        headers,
    });

    const data = await res.json().catch(() => ({}));
    if (! res.ok) {
        if (res.status === 401) {
            throw new APIUnauthorizedError((data as any)?.error || "Unauthorized");
        }
        throw new Error((data as any)?.error ||`HTTP ${res.status}`);
    }

    return data as T;
}

export async function apiGetBinary(path: string, init: RequestInit = {}) {
    const res = await apiFetch(path, init);

    if (!res.ok) {
        if (res.status === 401) {
            throw new APIUnauthorizedError();
        }
        let msg = `HTTP ${res.status}`;

        try {
            const t = await res.text();
            if (t) msg += ` ${t}`;
        } catch {
            //
        }

        throw new Error(msg);
    }

    const blob = await res.blob();
    const contentType = res.headers.get("Content-Type") || "";
    const cd = res.headers.get("Content-Disposition") || "";

    const mStar = cd.match(/filename\*\s*=\s*UTF-8''([^;]+)/i);
    const m = cd.match(/filename\s*=\s*"?(.*?)"?\s*(?:;|$)/i);
    const encoded = (mStar && mStar[1]) || (m && m[1]) || "";
    const filename = encoded ? decodeURIComponent(encoded) : undefined;

    return { blob, filename, contentType };
}
