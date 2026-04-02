type EnvLike = {
    VITE_CORAZA_API_BASE?: string;
    VITE_API_KEY?: string;
};

const env = ((import.meta as ImportMeta & { env?: EnvLike }).env ?? {});
const API_BASE = env.VITE_CORAZA_API_BASE || "/tukuyomi-api";
const API_KEY = env.VITE_API_KEY || "";

function withKey(headers: Headers) {
    if (API_KEY) {
        headers.set("X-API-Key", API_KEY);
    }
}

export async function apiGetText(path: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers || {});
    withKey(headers);

    const res = await fetch(`${API_BASE}${path}`, {
        ...init,
        headers,
        credentials: "include"
    });

    if (! res.ok) {
        throw new Error(`HTTP ${res.status}`);
    }

    return res.text();
}

export async function apiGetJson<T = any>(path: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers || {});
    withKey(headers);

    const res = await fetch(`${API_BASE}${path}`, {
        ...init,
        headers,
        credentials: 'include'
    });
    const data = await res.json().catch(() => ({}));

    if (! res.ok) {
        throw new Error((data as any)?.error || `HTTP ${res.status}`);
    }

    return data as T;
}

export async function apiPostText(path: string, body: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers || {});
    headers.set("Content-Type", "text/plain");
    withKey(headers);

    const res = await fetch(`${API_BASE}${path}`, {
        method: "POST",
        body, ...init,
        headers,
        credentials: "include"
    });

    if (! res.ok) {
        throw new Error(`HTTP ${res.status}`);
    }

    return res;
}

export async function apiPostJson<T = any>(path: string, body: unknown, init: RequestInit = {}) {
    const headers = new Headers(init.headers || {});
    headers.set("Content-Type", "application/json");
    withKey(headers)

    const res = await fetch(`${API_BASE}${path}`, {
        method: "POST",
        body: JSON.stringify(body),
        ...init,
        headers,
        credentials: "include",
    });

    const data = await res.json().catch(() => ({}));
    if (! res.ok) {
        throw new Error((data as any)?.error || `HTTP ${res.status}`);
    }

    return data as T;
}

export async function apiPutJson<T = any>(path: string, body: unknown, init: RequestInit = {}) {
    const headers = new Headers(init.headers ||{});
    headers.set("Content-Type", "application/json");
    withKey(headers);

    const res = await fetch(`${API_BASE}${path}`, {
        method: "PUT",
        body: JSON.stringify(body),
        ...init,
        headers,
        credentials: "include",
    });

    const data = await res.json().catch(() => ({}));
    if (! res.ok) {
        throw new Error((data as any)?.error ||`HTTP ${res.status}`);
    }

    return data as T;
}

export async function apiGetBinary(path: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers || {});
    withKey(headers);

    const res = await fetch(`${API_BASE}${path}`, {
        ...init,
        headers,
        credentials: "include",
    });

    if (!res.ok) {
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
