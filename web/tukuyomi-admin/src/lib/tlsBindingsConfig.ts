export type TLSBindingMode = "legacy" | "manual" | "acme";
export type TLSBindingACMEEnvironment = "production" | "staging";

export type TLSBindingEntry = {
  name: string;
  enabled: boolean;
  hosts: string[];
  mode: TLSBindingMode;
  cert_file?: string;
  key_file?: string;
  acme?: {
    environment?: TLSBindingACMEEnvironment;
    email?: string;
  };
};

export type TLSBindingStatus = {
  name: string;
  enabled: boolean;
  hosts?: string[];
  mode?: string;
  status?: string;
  warning?: string;
  cert_not_after?: string;
  acme_environment?: string;
};

export type TLSBindingsResponse = {
  etag?: string;
  raw?: string;
  tls_bindings?: {
    bindings?: TLSBindingEntry[];
  };
  tls_binding_statuses?: TLSBindingStatus[];
  rollback_depth?: number;
};

export function createEmptyTLSBinding(index: number): TLSBindingEntry {
  return {
    name: `tls-${index}`,
    enabled: true,
    hosts: [],
    mode: "acme",
    cert_file: "",
    key_file: "",
    acme: {
      environment: "production",
      email: "",
    },
  };
}

export function normalizeTLSBindings(bindings: TLSBindingEntry[]): TLSBindingEntry[] {
  return bindings.map((binding) => ({
    name: binding.name.trim(),
    enabled: !!binding.enabled,
    hosts: binding.hosts.map((host) => host.trim()).filter(Boolean),
    mode: binding.mode,
    cert_file: binding.cert_file?.trim() ?? "",
    key_file: binding.key_file?.trim() ?? "",
    acme: {
      environment: binding.acme?.environment ?? "production",
      email: binding.acme?.email?.trim() ?? "",
    },
  }));
}

export function tlsBindingsToRaw(bindings: TLSBindingEntry[]) {
  const normalized = normalizeTLSBindings(bindings).map((binding) => ({
    name: binding.name,
    enabled: binding.enabled,
    hosts: binding.hosts,
    mode: binding.mode,
    ...(binding.mode === "manual" && binding.cert_file ? { cert_file: binding.cert_file } : {}),
    ...(binding.mode === "manual" && binding.key_file ? { key_file: binding.key_file } : {}),
    ...(binding.mode === "acme"
      ? {
          acme: {
            environment: binding.acme?.environment ?? "production",
            ...(binding.acme?.email ? { email: binding.acme.email } : {}),
          },
        }
      : {}),
  }));
  return JSON.stringify({ bindings: normalized }, null, 2);
}

export function parseTLSBindingsResponse(data?: TLSBindingsResponse): TLSBindingEntry[] {
  if (data?.tls_bindings?.bindings) {
    return data.tls_bindings.bindings.map((binding, index) => ({
      ...createEmptyTLSBinding(index + 1),
      ...binding,
      enabled: binding.enabled !== false,
      hosts: Array.isArray(binding.hosts) ? binding.hosts : [],
      mode: (binding.mode ?? "legacy") as TLSBindingMode,
      cert_file: binding.cert_file ?? "",
      key_file: binding.key_file ?? "",
      acme: {
        environment: (binding.acme?.environment ?? "production") as TLSBindingACMEEnvironment,
        email: binding.acme?.email ?? "",
      },
    }));
  }
  return [];
}
