// AI & Providers: one place for the provider, connection status, default
// model, provider setup (Ollama/ChatGPT), API keys, and the model registry.
// The default-model select edits the shared draft (saved via the unsaved bar);
// provider switching and secrets save immediately, as before.

import { useState } from "react";
import { ChevronDown, ChevronRight, Loader2, Plus, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SettingsSection } from "./SettingsSection";
import { SettingRow } from "./SettingRow";
import { ConfigEditor } from "./ConfigEditor";
import { StatusDot } from "./StatusOverview";
import { useSettingsDraft } from "./useSettingsDraft";
import { ChatGptControls, OpenCodeGoControls, ProviderPicker, useDefaultModel, useModelOptions, useProviderStatus } from "@/components/ProviderSetup";
import { useAddModel, useLiveModels, useModels, usePutSecrets, useRemoveModel, useSecrets } from "@/api/hooks";
import { ApiError } from "@/api/client";
import { SkeletonRows } from "@/components/Loading";

export function ProviderSettings() {
  return (
    <div className="space-y-4">
      <SettingsSection title="AI provider" description="Which provider powers the agent, and the default model.">
        <ProviderStatusRow />
      </SettingsSection>
      <SettingsSection title="Provider API keys" description="Write-only — enter a new value to replace an existing key.">
        <SecretsEditor />
      </SettingsSection>
      <SettingsSection title="Model registry" description="Configured model aliases and live models.">
        <ModelRegistry />
      </SettingsSection>
      <ConfigEditor category="ai" />
    </div>
  );
}

function ProviderStatusRow() {
  const status = useProviderStatus();
  const { draft, update } = useSettingsDraft();
  const options = useModelOptions();
  const defaultModel = useDefaultModel();
  const [manageOpen, setManageOpen] = useState(false);

  const provider = status.provider;
  // Single read path (useDefaultModel); only the draft override is
  // provider-keyed, since each provider persists its default under its own
  // config key. Generic providers persist under providers.<id>.default_model.
  const draftOverride = (() => {
    if (provider === "chatgpt")
      return (draft.chatgpt as Record<string, unknown> | undefined)?.default_model as string | undefined;
    if (provider === "opencode_go")
      return (draft.opencode_go as Record<string, unknown> | undefined)?.default_model as string | undefined;
    if (provider === "ollama")
      return (draft.models as Record<string, unknown> | undefined)?.default_alias as string | undefined;
    const entry = (draft.providers as Record<string, unknown> | undefined)?.[provider];
    return (entry as Record<string, unknown> | undefined)?.default_model as string | undefined;
  })();
  const current = draftOverride ?? defaultModel;
  const all = current && !options.includes(current) ? [current, ...options] : options;

  const onDefaultModel = (value: string) => {
    if (provider === "chatgpt") update("chatgpt", "default_model", value);
    else if (provider === "opencode_go") update("opencode_go", "default_model", value);
    else if (provider === "ollama") update("models", "default_alias", value);
    else {
      const entry = ((draft.providers as Record<string, unknown> | undefined)?.[provider] ?? {}) as Record<
        string,
        unknown
      >;
      update("providers", provider, { ...entry, default_model: value });
    }
  };

  return (
    <div>
      <SettingRow label="Provider" description="The chat/generate provider for the agent.">
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 text-sm">
            {status.label}
            <StatusDot tone={status.online ? "ok" : status.error ? "bad" : "warn"} />
          </span>
          <span className="text-xs text-muted-foreground">
            {status.online ? `${status.liveCount} live models` : status.error ? "unreachable" : "offline"}
          </span>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => setManageOpen((v) => !v)}
            aria-expanded={manageOpen}
          >
            {manageOpen ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            Manage provider
          </Button>
        </div>
      </SettingRow>

      <SettingRow label="Default model" description="Used when no model is chosen for a run.">
        {all.length === 0 ? (
          <SelectTrigger disabled className="w-full sm:w-56">
            <SelectValue placeholder="No models" />
          </SelectTrigger>
        ) : (
          <Select value={current} onValueChange={onDefaultModel}>
            <SelectTrigger className="w-full sm:w-56" aria-label="Default model">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {all.map((m) => (
                <SelectItem key={m} value={m}>
                  {m}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </SettingRow>

      {manageOpen && (
        <div className="space-y-3 border-t py-3">
          <ProviderPicker />
          {provider === "chatgpt" ? (
            <ChatGptControls />
          ) : provider === "opencode_go" ? (
            <OpenCodeGoControls />
          ) : (
            <p className="text-xs text-muted-foreground">Local Ollama models. Embeddings also use Ollama.</p>
          )}
        </div>
      )}
    </div>
  );
}

function SecretsEditor() {
  const secrets = useSecrets();
  const put = usePutSecrets();
  const [draft, setDraft] = useState<Record<string, string>>({});
  const entries = Object.entries(secrets.data?.keys ?? {});

  const onSave = () => {
    const payload = Object.fromEntries(Object.entries(draft).filter(([, v]) => v.trim()));
    if (Object.keys(payload).length === 0) return;
    put.mutate(payload, { onSuccess: () => setDraft({}) });
  };

  if (secrets.isLoading) return <SkeletonRows count={2} className="py-3" />;
  if (secrets.error) return <div className="py-3 text-sm text-destructive">Failed to load secrets.</div>;
  if (entries.length === 0) return <p className="py-3 text-sm text-muted-foreground">No configured provider keys.</p>;

  return (
    <div className="space-y-3 py-3">
      {entries.map(([name, status]) => (
        <div key={name} className="grid gap-2 sm:grid-cols-[200px_1fr_auto]">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs">{name}</span>
            {status === "configured" ? (
              <Badge variant="success">
                <ShieldCheck className="h-3 w-3" />
                configured
              </Badge>
            ) : (
              <Badge variant="muted">missing</Badge>
            )}
          </div>
          <Input
            type="password"
            placeholder={status === "configured" ? "Write-only. Enter a new value to replace." : "Enter value"}
            value={draft[name] ?? ""}
            onChange={(e) => setDraft((p) => ({ ...p, [name]: e.target.value }))}
            autoComplete="off"
          />
          <Button size="sm" variant="outline" onClick={onSave} disabled={!draft[name]?.trim() || put.isPending}>
            Save
          </Button>
        </div>
      ))}
      {put.error && (
        <p className="text-xs text-destructive">{put.error instanceof ApiError ? put.error.message : "Save failed."}</p>
      )}
    </div>
  );
}

function ModelRegistry() {
  const models = useModels();
  const live = useLiveModels();
  const status = useProviderStatus();
  const addModel = useAddModel();
  const removeModel = useRemoveModel();
  const provider = models.data?.provider ?? "ollama";
  const isChatgpt = provider === "chatgpt";
  const isOpencodeGo = provider === "opencode_go";
  const isOllama = provider === "ollama";
  // Generic providers surface their configured models via the
  // active_provider block (no per-provider UI branches).
  const genericConfigured =
    !isChatgpt && !isOpencodeGo && !isOllama && models.data?.active_provider?.id === provider
      ? (models.data.active_provider.configured_models ?? [])
      : [];
  const registry = Object.entries(models.data?.registry ?? {});
  const registryMap = new Map(registry);
  const [newAlias, setNewAlias] = useState("");
  const [newModel, setNewModel] = useState("");
  const [confirmRemove, setConfirmRemove] = useState<string | null>(null);

  const onAdd = () => {
    const alias = newAlias.trim();
    const model = newModel.trim();
    if (!alias || !model) return;
    addModel.mutate({ alias, model }, { onSuccess: () => { setNewAlias(""); setNewModel(""); } });
  };

  return (
    <div className="space-y-4 py-3">
      <div>
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Live {status.label} models
          </span>
          <Button size="sm" variant="ghost" onClick={() => live.refetch()} disabled={live.isFetching}>
            <RefreshCw className={cn("h-3.5 w-3.5", live.isFetching && "animate-spin")} />
          </Button>
        </div>
        {live.data && (
          <div className="mt-1 flex items-center gap-2">
            <Badge variant="outline">{live.data.source}</Badge>
            {live.data.error && <span className="text-xs text-amber-200">{live.data.error}</span>}
          </div>
        )}
        <ul className="mt-1.5 space-y-1 font-mono text-xs">
          {(live.data?.models ?? []).map((m) => (
            <li key={m} className="rounded bg-muted/40 px-2 py-1">
              {m}
            </li>
          ))}
          {(live.data?.models ?? []).length === 0 && (
            <li className="text-muted-foreground">
              No models reported. {status.fixHint}
              {isOpencodeGo && " Uses https://opencode.ai/zen/go/v1/responses."}
            </li>
          )}
        </ul>
      </div>

      {isChatgpt ? (
        <div>
          <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Configured ChatGPT models</span>
          <ul className="mt-1.5 space-y-1 font-mono text-xs">
            {(models.data?.chatgpt?.configured_models ?? []).map((m) => (
              <li key={m} className="rounded bg-muted/40 px-2 py-1">
                {m}
              </li>
            ))}
            {(models.data?.chatgpt?.configured_models ?? []).length === 0 && (
              <li className="text-muted-foreground">Empty — models are discovered from /v1/models at run time.</li>
            )}
          </ul>
        </div>
      ) : isOpencodeGo ? (
        <div>
          <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Configured OpenCode Go models</span>
          <ul className="mt-1.5 space-y-1 font-mono text-xs">
            {(models.data?.opencode_go?.configured_models ?? []).map((m) => (
              <li key={m} className="rounded bg-muted/40 px-2 py-1">
                {m}
              </li>
            ))}
            {(models.data?.opencode_go?.configured_models ?? []).length === 0 && (
              <li className="text-muted-foreground">
                Empty — models are discovered from {models.data?.opencode_go?.base_url ?? "https://opencode.ai/zen/go/v1"}/models at run
                time (Responses API: muse-spark-1.2-contributor).
              </li>
            )}
          </ul>
          <p className="mt-2 text-xs text-muted-foreground">Registry editing for OpenCode Go uses opencode_go.models.</p>
        </div>
      ) : !isOllama ? (
        <div>
          <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Configured {status.label} models
          </span>
          <ul className="mt-1.5 space-y-1 font-mono text-xs">
            {genericConfigured.map((m) => (
              <li key={m} className="rounded bg-muted/40 px-2 py-1">
                {m}
              </li>
            ))}
            {genericConfigured.length === 0 && (
              <li className="text-muted-foreground">Empty — models are discovered at run time. {status.fixHint}</li>
            )}
          </ul>
        </div>
      ) : (
        <div>
          <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Registry</span>
          <div className="mt-2 flex flex-wrap items-end gap-2">
            <div className="min-w-[8rem] flex-1">
              <label htmlFor="new-alias" className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Alias
              </label>
              <Input
                id="new-alias"
                value={newAlias}
                onChange={(e) => setNewAlias(e.target.value)}
                placeholder="e.g. llama"
                className="h-8 font-mono text-xs"
              />
            </div>
            <div className="min-w-[12rem] flex-[2]">
              <label htmlFor="new-model" className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Model id
              </label>
              <Input
                id="new-model"
                value={newModel}
                onChange={(e) => setNewModel(e.target.value)}
                placeholder="e.g. llama3.1:8b"
                className="h-8 font-mono text-xs"
              />
            </div>
            <Button size="sm" onClick={onAdd} disabled={!newAlias.trim() || !newModel.trim() || addModel.isPending}>
              {addModel.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
              Add
            </Button>
          </div>
          {addModel.error && (
            <p className="mt-2 text-xs text-destructive">
              {addModel.error instanceof ApiError ? addModel.error.message : "Add failed."}
            </p>
          )}
          <ul className="mt-3 space-y-2 text-xs">
            {registry.map(([alias, model]) => {
              const info = models.data?.info?.[alias];
              const isDefault = alias === models.data?.default_alias;
              return (
                <li key={alias} className="rounded-md border p-2">
                  <div className="flex flex-wrap items-center gap-2 font-mono">
                    <span className="text-muted-foreground">{alias}</span>
                    <span>{String(model)}</span>
                    {isDefault && <Badge variant="success" className="text-[10px]">default</Badge>}
                    {info?.label && <span className="font-sans text-muted-foreground">{info.label}</span>}
                    {typeof info?.context_window === "number" && (
                      <span className="font-sans text-muted-foreground">{(info.context_window / 1000).toFixed(0)}K ctx</span>
                    )}
                    {!isDefault && (
                      <Button
                        size="sm"
                        variant="ghost"
                        className="ml-auto h-6 w-6 p-0 text-muted-foreground hover:text-destructive"
                        onClick={() => setConfirmRemove(alias)}
                        disabled={removeModel.isPending}
                        aria-label={`Remove ${alias}`}
                        title={`Remove ${alias}`}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </div>
                  {info?.description && <p className="mt-1 font-sans text-muted-foreground">{info.description}</p>}
                </li>
              );
            })}
          </ul>
          {removeModel.error && (
            <p className="mt-2 text-xs text-destructive">
              {removeModel.error instanceof ApiError ? removeModel.error.message : "Remove failed."}
            </p>
          )}
        </div>
      )}

      <Dialog open={confirmRemove !== null} onOpenChange={(open) => { if (!open) setConfirmRemove(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove model alias?</DialogTitle>
            <DialogDescription>
              Removes <span className="font-mono">{confirmRemove}</span>
              {confirmRemove && registryMap.get(confirmRemove) && (
                <> → <span className="font-mono">{registryMap.get(confirmRemove)}</span>
                  </>
              )}{" "}
              from the registry. Runs already started keep their configured model.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmRemove(null)}>Cancel</Button>
            <Button
              variant="destructive"
              disabled={removeModel.isPending}
              onClick={() => {
                if (confirmRemove) removeModel.mutate(confirmRemove);
                setConfirmRemove(null);
              }}
            >
              {removeModel.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
