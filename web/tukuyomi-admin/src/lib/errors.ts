export function getErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  if (typeof error === "string" && error) {
    return error;
  }
  return fallback;
}

export function isAbortLikeError(error: unknown): boolean {
  if (error === "refresh" || error === "unmount") {
    return true;
  }
  if (error instanceof Error && error.name === "AbortError") {
    return true;
  }
  if (typeof error !== "object" || error === null) {
    return false;
  }
  const name = "name" in error ? (error as { name?: unknown }).name : undefined;
  const code = "code" in error ? (error as { code?: unknown }).code : undefined;
  return name === "AbortError" || code === 20;
}
