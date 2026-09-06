// Subtle status overview — muted, text-xs, not a dashboard. Six items:
// AI, Models, Secrets, Plugins, Sandbox, Browser with small colored dots.

import { useBrowserStatus, usePlugins, useSandboxStatus, useSecrets } from "@/api/hooks";
import { useModelOptions, useProviderStatus } from "@/components/ProviderSetup";
import { cn } from "@/lib/utils";

export function StatusOverview() {
  const status = useProviderStatus();
  const modelOptions = useModelOptions();
  const secrets = useSecrets();
  const plugins = usePlugins();
  const sandbox = useSandboxStatus();
  const browser = useBrowserStatus();

  const secretEntries = Object.entries(secrets.data?.keys ?? {});
  const configured = secretEntries.filter(([, s]) => s === "configured").length;
  const pluginList = plugins.data?.plugins ?? [];
  const loaded = pluginList.filter((p) => p.loaded).length;
  const total = pluginList.length;
  // Provider-aware count: live models when online, else the provider's
  // configured/default options (never another provider's registry).
  const modelCount = status.liveCount > 0 ? status.liveCount : modelOptions.length;

  const sandboxEnabled = sandbox.data?.enabled ?? false;
  const sandboxTone: "ok" | "warn" | "bad" = !sandboxEnabled
    ? "warn"
    : sandbox.data?.docker_available
      ? "ok"
      : "bad";
  const sandboxValue = !sandboxEnabled ? "Off" : sandbox.data?.docker_available ? "Contained" : "Unreachable";

  const secretsValue =
    secretEntries.length === 0 ? "\u2014" : configured === secretEntries.length ? "OK" : `${configured}/${secretEntries.length}`;
  const secretsTone: "ok" | "warn" | "bad" =
    secretEntries.length === 0 ? "warn" : configured === secretEntries.length ? "ok" : "warn";

  const browserEnabled = browser.data?.enabled ?? false;
  const browserTone: "ok" | "warn" | "bad" = !browserEnabled ? "warn" : browser.data?.available ? "ok" : "bad";
  const browserValue = !browserEnabled ? "Off" : browser.data?.available ? "Ready" : "Not ready";

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-muted-foreground">
      <StatusItem
        tone={status.online ? "ok" : status.error ? "bad" : "warn"}
        label="AI"
        value={status.online ? status.label : status.error ? "Unreachable" : "Offline"}
      />
      <StatusItem tone="ok" label="Models" value={`${modelCount}`} />
      <StatusItem tone={secretsTone} label="Secrets" value={secretsValue} />
      <StatusItem tone="ok" label="Plugins" value={`${loaded}/${total}`} />
      <StatusItem tone={sandboxTone} label="Sandbox" value={sandboxValue} />
      <StatusItem tone={browserTone} label="Browser" value={browserValue} />
    </div>
  );
}

export function StatusDot({ tone }: { tone: "ok" | "warn" | "bad" }) {
  return (
    <span
      className={cn(
        "inline-block h-1.5 w-1.5 rounded-full",
        tone === "ok" ? "bg-emerald-400" : tone === "warn" ? "bg-amber-400" : "bg-destructive",
      )}
      aria-hidden
    />
  );
}

function StatusItem({ tone, label, value }: { tone: "ok" | "warn" | "bad"; label: string; value: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs">
      <StatusDot tone={tone} />
      <span className="font-medium text-foreground">{label}</span>
      <span className="text-muted-foreground">{value}</span>
    </span>
  );
}
