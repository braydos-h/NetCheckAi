import { useState, type ReactNode } from "react";
import { Loader2, Terminal } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { CopyButton } from "@/components/CopyButton";
import { Spinner } from "@/components/Loading";

interface AdvisoryPanelProps {
  tools: Array<{ function?: { name: string; description?: string; parameters?: Record<string, unknown> } }>;
  toolsLoading: boolean;
  /** Tool-list fetch failure — surfaced with a retry like the other tabs. */
  toolsError?: unknown;
  onRetryTools?: () => void;
  features: string[];
  runActive: boolean;
  onCall: (name: string, args: Record<string, unknown>) => void;
  calling: boolean;
  lastResult: string;
}

const ADVISORY_TOOLS: Array<{ name: string; feature: string; label: string; args: string; render: (r: string) => ReactNode }> = [
  {
    name: "verify_poc",
    feature: "poc_verification",
    label: "Verify PoC",
    args: JSON.stringify({ code: "# paste a synthesized PoC here\n", image: "" }),
    render: (r) => <PocVerifyResult result={r} />,
  },
  {
    name: "replay_simulate",
    feature: "replay_simulator",
    label: "Replay simulate",
    args: JSON.stringify({ plan_json: "{}", recon_json: "{}" }),
    render: (r) => <ReplaySimResult result={r} />,
  },
  {
    name: "peer_review_outcome",
    feature: "peer_review",
    label: "Peer review outcome",
    args: JSON.stringify({ verdict: "compromised", evidence: "" }),
    render: (r) => <KeyValueResult result={r} title="PEER_REVIEW_OUTCOME" />,
  },
  {
    name: "export_attack_navigator",
    feature: "mitre",
    label: "Export ATT&CK Navigator",
    args: JSON.stringify({ target_ip: "", output_path: "" }),
    render: (r) => <NavigatorResult result={r} />,
  },
  {
    name: "search_threat_intel",
    feature: "threat_intel",
    label: "Search threat intel",
    args: JSON.stringify({ query: "log4j", sources: "osv,ghsa,kev" }),
    render: (r) => <JsonResult result={r} />,
  },
];

export function AdvisoryPanel({ tools, toolsLoading, toolsError, onRetryTools, features, runActive, onCall, calling, lastResult }: AdvisoryPanelProps) {
  const [selected, setSelected] = useState<string>("");
  const [args, setArgs] = useState<string>("{}");
  const [result, setResult] = useState<string>("");

  const toolNames = new Set(tools.map((t) => t.function?.name ?? ""));
  const available = ADVISORY_TOOLS.filter((t) => features.includes(t.feature));
  const activeTool = ADVISORY_TOOLS.find((t) => t.name === selected);

  if (toolsError) {
    return (
      <div className="flex items-center gap-2 text-sm text-destructive">
        <span>Failed to load tools.</span>
        {onRetryTools && (
          <Button size="sm" variant="outline" onClick={onRetryTools}>Retry</Button>
        )}
      </div>
    );
  }

  if (!runActive && tools.length === 0) {
    return (
      <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
        Advisory tools are available only while a run is active and the MCP session is attached.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        {available.map((t) => {
          const registered = toolNames.has(t.name);
          return (
            <Button
              key={t.name}
              type="button"
              variant={selected === t.name ? "default" : "outline"}
              size="sm"
              className="font-mono text-xs"
              disabled={!registered}
              title={registered ? t.label : `${t.name} not registered in this run`}
              onClick={() => {
                setSelected(t.name);
                setArgs(t.args);
                setResult("");
              }}
            >
              {t.label}
            </Button>
          );
        })}
        {available.length === 0 && <p className="text-xs text-muted-foreground">No advisory features enabled in capabilities.</p>}
      </div>

      {activeTool && (
        <>
          {toolsLoading && <Spinner label="Loading tool schemas..." />}
          <div className="space-y-2">
            <Label className="text-xs" htmlFor="adv-args">
              Arguments (JSON)
            </Label>
            <Textarea
              id="adv-args"
              value={args}
              onChange={(e) => setArgs(e.target.value)}
              className="min-h-[6rem] font-mono text-xs"
              spellCheck={false}
            />
            <Button
              type="button"
              size="sm"
              disabled={!selected || calling || !toolNames.has(selected)}
              onClick={() => {
                let parsed: Record<string, unknown> = {};
                try {
                  parsed = args.trim() ? JSON.parse(args) : {};
                } catch {
                  setResult("Invalid JSON arguments.");
                  return;
                }
                setResult("");
                onCall(selected, parsed);
              }}
            >
              {calling ? <Loader2 className="h-4 w-4 animate-spin" /> : <Terminal className="h-4 w-4" />}
              Run {activeTool.label}
            </Button>
          </div>
          {(result || lastResult) && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <Label className="text-xs">Result</Label>
                <CopyButton value={result || lastResult} size="sm" />
              </div>
              {activeTool.render(result || lastResult)}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function PocVerifyResult({ result }: { result: string }) {
  const ok = /SYNTAX_OK:\s*true/i.test(result) || /syntax_ok.*true/i.test(result);
  const dockerOk = /docker_ok:\s*true|DOCKER_OK:\s*true/i.test(result);
  return (
    <div className="space-y-2 rounded-md border bg-muted/40 p-3 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={ok ? "success" : "danger"}>{ok ? "Syntax OK" : "Syntax FAIL"}</Badge>
        {/docker/i.test(result) && <Badge variant={dockerOk ? "success" : "muted"}>{dockerOk ? "Docker OK" : "Docker FAIL"}</Badge>}
        {/BLOCKED:/.test(result) && <Badge variant="warn">Blocked</Badge>}
      </div>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words font-mono scrollbar-thin">{result}</pre>
    </div>
  );
}

function ReplaySimResult({ result }: { result: string }) {
  const m = result.match(/confidence[:\s]*([0-9.]+)/i);
  const conf = m ? parseFloat(m[1] ?? "") : null;
  return (
    <div className="space-y-2 rounded-md border bg-muted/40 p-3 text-xs">
      {conf != null && (
        <div className="flex items-center gap-2">
          <Badge variant={conf >= 0.7 ? "success" : conf >= 0.4 ? "warn" : "danger"} className="tabular-nums">
            confidence {conf.toFixed(2)}
          </Badge>
        </div>
      )}
      {/BLOCKED:/.test(result) && <Badge variant="warn">Blocked</Badge>}
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words font-mono scrollbar-thin">{result}</pre>
    </div>
  );
}

function NavigatorResult({ result }: { result: string }) {
  const pathMatch = result.match(/layer_path:\s*(\S+)/);
  return (
    <div className="space-y-2 rounded-md border bg-muted/40 p-3 text-xs">
      {pathMatch && (
        <div className="flex items-center gap-2">
          <Badge variant="info">Layer written</Badge>
          <span className="truncate font-mono text-muted-foreground" title={pathMatch[1]}>
            {pathMatch[1]}
          </span>
        </div>
      )}
      <p className="text-muted-foreground">Open the layer JSON in ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/).</p>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words font-mono scrollbar-thin">{result}</pre>
    </div>
  );
}

function KeyValueResult({ result, title }: { result: string; title: string }) {
  const status = result.startsWith(`${title}: COMPLETED`)
    ? "success"
    : result.startsWith(`${title}: BLOCKED`)
      ? "warn"
      : result.startsWith(`${title}: DISABLED`)
        ? "muted"
        : result.startsWith(`${title}: UNAVAILABLE`)
          ? "muted"
          : result.startsWith(`${title}: BUDGET_EXHAUSTED`)
            ? "warn"
            : "outline";
  return (
    <div className="space-y-2 rounded-md border bg-muted/40 p-3 text-xs">
      <Badge variant={status as "success" | "warn" | "muted" | "outline"}>{result.split("\n")[0]}</Badge>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words font-mono scrollbar-thin">{result}</pre>
    </div>
  );
}

function JsonResult({ result }: { result: string }) {
  let pretty = result;
  try {
    const parsed = JSON.parse(result);
    pretty = JSON.stringify(parsed, null, 2);
  } catch {
    /* not pure JSON — show raw */
  }
  return (
    <pre className="max-h-80 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin">
      {pretty}
    </pre>
  );
}
