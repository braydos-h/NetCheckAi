import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        destructive: "border-transparent bg-destructive text-destructive-foreground",
        outline: "text-foreground",
        success: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
        warn: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
        danger: "border-destructive/40 bg-destructive/10 text-red-700 dark:text-red-300",
        info: "border-primary/40 bg-primary/10 text-primary",
        muted: "border-muted-foreground/30 text-muted-foreground",
        violet: "border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };