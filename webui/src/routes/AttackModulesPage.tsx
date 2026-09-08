import { useMemo, useState } from "react";
import { BookOpen, ShieldAlert, Target } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { SkeletonRows } from "@/components/Loading";
import { useAttackModules } from "@/api/hooks";
import type { AttackModuleSummary } from "@/api/types";

const FAMILY_LABELS: Record<string, string> = {
  web: "Web",
  network_smb: "SMB / Network",
  services: "Network Services",
  ssh: "SSH",
  auth_creds: "Credentials",
  privesc: "Privilege Escalation",
  persistence: "Persistence",
  crypto_jwt: "Crypto / JWT",
  deserialize: "Deserialization",
  synthesis: "Exploit Synthesis",
  ics_iot: "ICS / IoT",
  supply_chain: "Supply Chain",
  detection: "Detection",
  orchestrator_phases: "Orchestration",
  ad: "Active Directory",
};

export function AttackModulesPage() {
  const modules = useAttackModules();
  const [query, setQuery] = useState("");
  const [family, setFamily] = useState<string>("all");

  const list = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (modules.data?.modules ?? []).filter((m) => {
      if (family !== "all" && m.family !== family) return false;
      if (!q) return true;
      const hay = [m.name, m.description, ...m.target_services, ...m.required_cves].join(" ").toLowerCase();
      return hay.includes(q);
    });
  }, [modules.data, query, family]);

  const families = useMemo(() => {
    const seen = new Set<string>();
    for (const m of modules.data?.modules ?? []) if (m.family) seen.add(m.family);
    return Array.from(seen).sort();
  }, [modules.data]);

  return (
    <div className="space-y-4 p-4 md:p-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">Attack Modules</h1>
          <p className="text-sm text-muted-foreground">
            Pre-packaged exploit recipes the agent can run. {modules.data?.modules.length ?? "—"} registered modules in{" "}
            {families.length} families.
          </p>
        </div>
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search modules, services, CVEs..."
          className="h-8 w-full max-w-xs"
        />
      </div>

      <div className="flex flex-wrap gap-1.5">
        <FamilyChip active={family === "all"} onClick={() => setFamily("all")} label={`All (${modules.data?.modules.length ?? 0})`} />
        {families.map((f) => (
          <FamilyChip
            key={f}
            active={family === f}
            onClick={() => setFamily(f)}
            label={`${FAMILY_LABELS[f] ?? f} (${(modules.data?.modules ?? []).filter((m) => m.family === f).length})`}
          />
        ))}
      </div>

      {modules.isLoading && <SkeletonRows count={8} />}
      {modules.error && (
        <div className="flex items-center gap-2 text-sm text-destructive">
          <span>Failed to load attack modules.</span>
          <button type="button" onClick={() => modules.refetch()} className="rounded-md border px-2 py-1 text-xs hover:bg-accent">
            Retry
          </button>
        </div>
      )}
      {!modules.isLoading && !modules.error && list.length === 0 && (
        <p className="text-sm text-muted-foreground">No modules match.</p>
      )}

      <div className="grid gap-2.5">
        {list.map((m) => (
          <ModuleRow key={m.name} mod={m} />
        ))}
      </div>
    </div>
  );
}

function FamilyChip({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "rounded-full border px-2.5 py-1 text-xs transition-colors",
        active
          ? "border-primary/60 bg-primary/10 text-primary"
          : "border-border text-muted-foreground hover:bg-accent hover:text-foreground",
      )}
    >
      {label}
    </button>
  );
}

function ModuleRow({ mod }: { mod: AttackModuleSummary }) {
  return (
    <Card className="bg-card/40">
      <CardContent className="p-3.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm font-semibold">{mod.name}</span>
          <Badge variant="outline" className="text-[10px]">
            {FAMILY_LABELS[mod.family] ?? mod.family}
          </Badge>
          {mod.destructive_ics && (
            <Badge variant="danger" className="text-[10px]">
              <ShieldAlert className="h-3 w-3" /> destructive ICS
            </Badge>
          )}
        </div>
        <p className="mt-1 text-sm text-muted-foreground">{mod.description}</p>
        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1">
            <Target className="h-3 w-3" />
            Services: {mod.target_services.length ? mod.target_services.join(", ") : "any"}
          </span>
          {mod.target_ports.length > 0 && <span>Ports: {mod.target_ports.join(", ")}</span>}
          {mod.required_cves.length > 0 && (
            <span className="inline-flex items-center gap-1">
              <BookOpen className="h-3 w-3" />
              CVEs: {mod.required_cves.join(", ")}
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
