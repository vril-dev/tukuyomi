import type { ReactNode } from "react";

export function SectionCard({
  title,
  subtitle,
  actions,
  children,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-2xl border border-neutral-200 bg-white p-4 shadow-sm space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">{title}</h2>
          {subtitle ? <p className="text-sm text-neutral-500">{subtitle}</p> : null}
        </div>
        {actions ? <div>{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="grid gap-1">
      <span className="text-sm font-medium">{label}</span>
      {children}
      {hint ? <span className="text-xs text-neutral-500">{hint}</span> : null}
    </label>
  );
}

export function StatBox({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-neutral-200 bg-neutral-50 px-3 py-2">
      <div className="text-xs uppercase tracking-wide text-neutral-500">{label}</div>
      <div className="text-sm font-medium break-all">{value}</div>
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="rounded-xl border border-dashed border-neutral-300 bg-neutral-50 px-4 py-6 text-sm text-neutral-500">{children}</div>;
}

export function Badge({ color, children }: { color: "gray" | "green" | "red" | "amber"; children: ReactNode }) {
  const cls =
    color === "green"
      ? "bg-green-100 text-green-800"
      : color === "red"
        ? "bg-red-100 text-red-800"
        : color === "amber"
          ? "bg-amber-100 text-amber-800"
          : "bg-neutral-100 text-neutral-700";
  return <span className={`px-2 py-0.5 text-xs rounded ${cls}`}>{children}</span>;
}

export function NoticeBar({
  tone,
  className = "",
  children,
}: {
  tone: "success" | "error" | "warn";
  className?: string;
  children: ReactNode;
}) {
  const cls =
    tone === "success"
      ? "border-green-300 bg-green-50 text-green-900"
      : tone === "error"
        ? "border-red-300 bg-red-50 text-red-900"
        : "border-amber-300 bg-amber-50 text-amber-900";
  return <div className={`rounded border px-3 py-2 text-xs whitespace-pre-wrap ${cls} ${className}`.trim()}>{children}</div>;
}

export function ActionResultNotice({
  tone,
  messages,
  className = "",
}: {
  tone: "success" | "error" | "warn";
  messages?: string | string[] | null;
  className?: string;
}) {
  const lines = Array.isArray(messages) ? messages.filter(Boolean) : typeof messages === "string" && messages.trim() ? [messages] : [];
  if (lines.length === 0) {
    return null;
  }
  return (
    <NoticeBar tone={tone} className={className}>
      {lines.map((message, index) => (
        <div key={`${message}-${index}`}>{message}</div>
      ))}
    </NoticeBar>
  );
}

export function MonoTag({ label, value }: { label: string; value: string }) {
  return (
    <div className="hidden md:flex items-center gap-1 text-xs">
      <span className="text-neutral-500">{label}:</span>
      <code className="px-2 py-0.5 bg-neutral-100 rounded max-w-[420px] truncate">{value}</code>
    </div>
  );
}

export function ActionButton({
  children,
  disabled,
  onClick,
}: {
  children: ReactNode;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button type="button" className="px-3 py-1.5 rounded-xl shadow text-sm hover:bg-neutral-50 border disabled:opacity-50" onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}

export function PrimaryButton({
  children,
  disabled,
  onClick,
}: {
  children: ReactNode;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button type="button" className="px-3 py-1.5 rounded-xl shadow text-sm bg-black text-white disabled:opacity-50" onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}

export function Alert({
  kind,
  title,
  message,
  onClose,
  closeLabel,
}: {
  kind: "error" | "info";
  title: string;
  message: string;
  onClose?: () => void;
  closeLabel: string;
}) {
  const cls = kind === "error" ? "border-red-300 bg-red-50" : "border-blue-300 bg-blue-50";
  return (
    <div className={`border ${cls} rounded-xl p-3 text-sm flex items-start gap-3`}>
      <div className="font-semibold">{title}</div>
      <div className="flex-1 whitespace-pre-wrap">{message}</div>
      {onClose ? (
        <button className="text-xs text-neutral-500 hover:underline" onClick={onClose}>
          {closeLabel}
        </button>
      ) : null}
    </div>
  );
}

export const inputClass = "w-full rounded-xl border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-black/20";
export const textareaClass = "w-full min-h-24 rounded-xl border px-3 py-2 font-mono text-sm outline-none focus:ring-2 focus:ring-black/20";
