import { getErrorMessage } from "./errors.js";

export async function runFPTunerApply<T>({
  applyRequest,
  refreshAudit,
  onSuccess,
  onError,
  fallbackMessage = "Apply failed",
}: {
  applyRequest: () => Promise<T>;
  refreshAudit: () => Promise<void>;
  onSuccess: (result: T) => void | Promise<void>;
  onError: (message: string) => void | Promise<void>;
  fallbackMessage?: string;
}) {
  try {
    const result = await applyRequest();
    await onSuccess(result);
  } catch (error: unknown) {
    await onError(getErrorMessage(error, fallbackMessage));
  } finally {
    await refreshAudit();
  }
}
