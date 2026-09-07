import { CheckCircle2, Loader2, PauseCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { stateCategory, type RunState } from "@/api/types";

const CATEGORY_VARIANT: Record<"pending" | "active" | "done", BadgeProps["variant"]> = {
  pending: "muted",
  active: "warn",
  done: "secondary",
};

const DONE_VARIANT: Partial<Record<RunState, BadgeProps["variant"]>> = {
  completed: "success",
  failed: "danger",
  cancelled: "muted",
  interrupted: "warn",
};

interface StatusBadgeProps {
  state: RunState;
  className?: string;
}

export function StatusBadge({ state, className }: StatusBadgeProps) {
  const category = stateCategory(state);
  const variant = category === "done" ? (DONE_VARIANT[state] ?? "secondary") : CATEGORY_VARIANT[category];
  const Icon = category === "done" ? CheckCircle2 : category === "active" ? Loader2 : PauseCircle;
  return (
    <Badge variant={variant} className={cn("gap-1 tabular-nums", className)}>
      <Icon className="h-3 w-3" aria-hidden />
      {state}
    </Badge>
  );
}