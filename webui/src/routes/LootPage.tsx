import { Link, useParams } from "react-router-dom";
import { ChevronLeft, Expand, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CredentialTable } from "@/components/CredentialTable";
import { SkeletonCards } from "@/components/Loading";
import { useLoot } from "@/api/hooks";
import { ApiError } from "@/api/client";
import { useState } from "react";

export function LootPage() {
  const { runId } = useParams<{ runId: string }>();
  const loot = useLoot(runId ?? null);
  // Keyed by the stable loot key (timestamp/type/host), not the list index,
  // so a refetch that reorders rows can't flip which card is expanded.
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  return (
    <div className="space-y-4 p-4 md:p-6">
      <div className="flex items-center gap-2">
        <Button asChild size="sm" variant="ghost">
          <Link to={`/runs/${runId}`}><ChevronLeft className="h-4 w-4" />Back to run</Link>
        </Button>
        <h1 className="text-sm font-mono text-muted-foreground">{runId}</h1>
        <Button size="sm" variant="ghost" onClick={() => loot.refetch()} disabled={loot.isFetching} aria-label="Refresh loot">
          <RefreshCw className={cn("h-3.5 w-3.5", loot.isFetching && "animate-spin")} />
        </Button>
      </div>

      <section className="space-y-2">
        <h2 className="text-sm font-semibold">Credentials</h2>
        <CredentialTable runId={runId ?? ""} />
      </section>

      <section className="space-y-2">
        <h2 className="text-sm font-semibold">Loot</h2>
        {loot.isLoading && <SkeletonCards count={2} />}
        {loot.error && (
          <div className="flex items-center gap-2 text-sm text-destructive">
            <span>{loot.error instanceof ApiError ? loot.error.message : "Failed to load loot."}</span>
            <Button size="sm" variant="outline" onClick={() => loot.refetch()}>Retry</Button>
          </div>
        )}
        {!loot.isLoading && (loot.data?.loot.length ?? 0) === 0 && (
          <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">No loot captured.</div>
        )}
        {(loot.data?.loot.length ?? 0) > 0 && (
          <div className="space-y-2">
            {loot.data?.loot.map((item, i) => {
              const key = `${item.timestamp ?? i}-${item.loot_type}-${item.source_host ?? ""}`;
              const isOpen = !!expanded[key];
              return (
                <Card key={key}>
                  <CardHeader className="pb-2">
                    <div className="flex items-center gap-2">
                      <CardTitle className="text-xs font-mono">{item.loot_type}</CardTitle>
                      <span className="truncate text-xs text-muted-foreground">{item.description}</span>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="ml-auto h-7"
                        onClick={() => setExpanded((p) => ({ ...p, [key]: !p[key] }))}
                        aria-label={isOpen ? "Collapse" : "Expand"}
                      >
                        <Expand className={cn("h-3.5 w-3.5 transition-transform", isOpen && "rotate-180")} />
                      </Button>
                    </div>
                  </CardHeader>
                  {isOpen && (
                    <CardContent>
                      <pre className="max-h-60 overflow-auto rounded-md bg-muted/40 p-2 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin">
                        {String(item.content ?? item.path ?? "")}
                      </pre>
                    </CardContent>
                  )}
                </Card>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}