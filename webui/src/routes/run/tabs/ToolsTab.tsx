import { Loader2, Terminal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { CopyButton } from "@/components/CopyButton";
import { Spinner } from "@/components/Loading";

interface ManualToolPanelProps {
  runId: string;
  tools: Array<{ function?: { name: string; description?: string; parameters?: Record<string, unknown> } }>;
  isLoading: boolean;
  /** Tool-list fetch failure — surfaced with a retry like the other tabs. */
  toolsError?: unknown;
  onRetryTools?: () => void;
  selectedTool: string;
  onSelect: (name: string) => void;
  args: string;
  onArgs: (args: string) => void;
  result: string;
  onResult: (result: string) => void;
  onCall: (name: string, args: Record<string, unknown>) => void;
  calling: boolean;
}

export function ManualToolPanel({
  tools,
  isLoading,
  toolsError,
  onRetryTools,
  selectedTool,
  onSelect,
  args,
  onArgs,
  result,
  onResult,
  onCall,
  calling,
}: ManualToolPanelProps) {
  const tool = tools.find((t) => t.function?.name === selectedTool);

  const call = () => {
    if (!selectedTool) return;
    let parsed: Record<string, unknown> = {};
    try {
      parsed = args.trim() ? JSON.parse(args) : {};
    } catch {
      onResult("Invalid JSON arguments.");
      return;
    }
    onCall(selectedTool, parsed);
  };

  if (isLoading) return <Spinner label="Loading tools..." />;
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
  if (tools.length === 0) {
    return (
      <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
        No live MCP tools. Tools are available only while a run is active and the MCP session is attached.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="space-y-2">
        <Label className="text-xs">Tool</Label>
        <div className="flex flex-wrap gap-2">
          {tools.map((t) => (
            <Button
              key={t.function?.name}
              type="button"
              variant={selectedTool === t.function?.name ? "default" : "outline"}
              size="sm"
              className="font-mono text-xs"
              onClick={() => {
                onSelect(t.function?.name ?? "");
                onArgs("{}");
                onResult("");
              }}
            >
              {t.function?.name}
            </Button>
          ))}
        </div>
        {tool?.function?.description && <p className="text-xs text-muted-foreground">{tool.function.description}</p>}
      </div>
      <div className="space-y-2">
        <Label className="text-xs" htmlFor="tool-args">
          Arguments (JSON)
        </Label>
        <Textarea
          id="tool-args"
          value={args}
          onChange={(e) => onArgs(e.target.value)}
          className="min-h-[6rem] font-mono text-xs"
          spellCheck={false}
        />
      </div>
      <Button type="button" size="sm" onClick={call} disabled={!selectedTool || calling}>
        {calling ? <Loader2 className="h-4 w-4 animate-spin" /> : <Terminal className="h-4 w-4" />}
        Run tool
      </Button>
      {result && (
        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <Label className="text-xs">Result</Label>
            <CopyButton value={result} size="sm" />
          </div>
          <pre className="max-h-72 overflow-auto rounded-md border bg-muted/40 p-2 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin">
            {result}
          </pre>
        </div>
      )}
    </div>
  );
}
