const API_BASE = "/tukuyomi-api";
const CSRF_COOKIE_NAME = "tukuyomi_admin_csrf";
const OPERATOR_IDENTITY_STORAGE_KEY = "tukuyomi_operator_identity";

let runtimeOperatorIdentity = "";

export const AUTH_REQUIRED_EVENT = "tukuyomi-admin-auth-required";

export class APIUnauthorizedError extends Error {
  constructor(message = "Unauthorized") {
    super(message);
    this.name = "APIUnauthorizedError";
  }
}

function appendAPIErrorMessage(messages: string[], value: unknown) {
  if (typeof value !== "string") {
    return;
  }
  const trimmed = value.trim();
  if (!trimmed || messages.includes(trimmed)) {
    return;
  }
  messages.push(trimmed);
}

function extractAPIErrorMessage(payload: unknown, status: number) {
  const messages: string[] = [];
  if (payload && typeof payload === "object") {
    const record = payload as Record<string, unknown>;
    appendAPIErrorMessage(messages, record.error);
    appendAPIErrorMessage(messages, record.message);
    if (Array.isArray(record.messages)) {
      for (const entry of record.messages) {
        appendAPIErrorMessage(messages, entry);
      }
    }
  }
  return messages.length ? messages.join("; ") : `HTTP ${status}`;
}

async function readAPIErrorMessage(res: Response, payload?: unknown) {
  if (typeof payload !== "undefined") {
    return extractAPIErrorMessage(payload, res.status);
  }
  const contentType = (res.headers.get("Content-Type") || "").toLowerCase();
  if (contentType.includes("application/json")) {
    const data = await res.json().catch(() => ({}));
    return extractAPIErrorMessage(data, res.status);
  }
  const text = (await res.text().catch(() => "")).trim();
  return text || `HTTP ${res.status}`;
}

function canUseStorage() {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
}

function readStoredOperatorIdentity() {
  if (!canUseStorage()) {
    return "";
  }
  try {
    return (window.localStorage.getItem(OPERATOR_IDENTITY_STORAGE_KEY) || "").trim();
  } catch {
    return "";
  }
}

runtimeOperatorIdentity = readStoredOperatorIdentity();

export function getAPIBasePath() {
  return API_BASE;
}

export function getOperatorIdentity() {
  return runtimeOperatorIdentity;
}

export function setOperatorIdentity(raw: string) {
  runtimeOperatorIdentity = (raw || "").trim();
  if (!canUseStorage()) {
    return;
  }
  try {
    if (runtimeOperatorIdentity) {
      window.localStorage.setItem(OPERATOR_IDENTITY_STORAGE_KEY, runtimeOperatorIdentity);
    } else {
      window.localStorage.removeItem(OPERATOR_IDENTITY_STORAGE_KEY);
    }
  } catch {
    // ignore storage errors
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

function withAdminHeaders(headers: Headers) {
  if (runtimeOperatorIdentity) {
    headers.set("X-Tukuyomi-Actor", runtimeOperatorIdentity);
  }
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
  withAdminHeaders(headers);
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

  if (!res.ok) {
    const message = await readAPIErrorMessage(res);
    if (res.status === 401) {
      throw new APIUnauthorizedError(message);
    }
    throw new Error(message);
  }

  return res.text();
}

export async function apiGetJson<T = unknown>(path: string, init: RequestInit = {}) {
  const res = await apiFetch(path, init);
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const message = await readAPIErrorMessage(res, data);
    if (res.status === 401) {
      throw new APIUnauthorizedError(message);
    }
    throw new Error(message);
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

  if (!res.ok) {
    const message = await readAPIErrorMessage(res);
    if (res.status === 401) {
      throw new APIUnauthorizedError(message);
    }
    throw new Error(message);
  }

  return res;
}

export async function apiPostJson<T = unknown>(path: string, body: unknown, init: RequestInit = {}) {
  const headers = new Headers(init.headers || {});
  headers.set("Content-Type", "application/json");

  const res = await apiFetch(path, {
    method: "POST",
    body: JSON.stringify(body),
    ...init,
    headers,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = await readAPIErrorMessage(res, data);
    if (res.status === 401) {
      throw new APIUnauthorizedError(message);
    }
    throw new Error(message);
  }

  return data as T;
}

export async function apiPutJson<T = unknown>(path: string, body: unknown, init: RequestInit = {}) {
  const headers = new Headers(init.headers || {});
  headers.set("Content-Type", "application/json");

  const res = await apiFetch(path, {
    method: "PUT",
    body: JSON.stringify(body),
    ...init,
    headers,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = await readAPIErrorMessage(res, data);
    if (res.status === 401) {
      throw new APIUnauthorizedError(message);
    }
    throw new Error(message);
  }

  return data as T;
}

export async function apiDeleteJson<T = unknown>(path: string, init: RequestInit = {}) {
  const res = await apiFetch(path, {
    method: "DELETE",
    ...init,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = await readAPIErrorMessage(res, data);
    if (res.status === 401) {
      throw new APIUnauthorizedError(message);
    }
    throw new Error(message);
  }

  return data as T;
}

export async function apiPostFormData<T = unknown>(path: string, form: FormData, init: RequestInit = {}) {
  const headers = new Headers(init.headers || {});

  const res = await apiFetch(path, {
    method: "POST",
    body: form,
    ...init,
    headers,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message = await readAPIErrorMessage(res, data);
    if (res.status === 401) {
      throw new APIUnauthorizedError(message);
    }
    throw new Error(message);
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
