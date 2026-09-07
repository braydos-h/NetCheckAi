interface SparklineProps {
  label: string;
  values: number[];
  format?: (v: number) => string;
  className?: string;
}

/** Minimal inline sparkline (pure SVG, no chart lib). */
export function Sparkline({ label, values, format, className }: SparklineProps) {
  if (values.length < 2) return null;
  let min = values[0] ?? 0;
  let max = values[0] ?? 0;
  for (let i = 1; i < values.length; i++) {
    const v = values[i] ?? 0;
    if (v < min) min = v;
    if (v > max) max = v;
  }
  const span = max - min || 1;
  const W = 120;
  const H = 28;
  const points = values
    .map((v, i) => {
      const x = (i / (values.length - 1)) * (W - 2) + 1;
      const y = H - 2 - ((v - min) / span) * (H - 4);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <div className={className}>
      <div className="flex items-center justify-between text-[10px] uppercase tracking-wide text-muted-foreground">
        <span>{label}</span>
        <span className="tabular-nums text-foreground">
          {format ? format(values[values.length - 1] ?? 0) : (values[values.length - 1] ?? 0).toLocaleString()}
        </span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-7 w-full" role="img" aria-label={`${label} over time: min ${min.toLocaleString()}, max ${max.toLocaleString()}, latest ${(values[values.length - 1] ?? 0).toLocaleString()}`}>
        <title>{`${label}: min ${min.toLocaleString()}, max ${max.toLocaleString()}, latest ${(values[values.length - 1] ?? 0).toLocaleString()}`}</title>
        <polyline
          points={points}
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          strokeLinejoin="round"
          strokeLinecap="round"
          className="text-primary/80"
        />
      </svg>
    </div>
  );
}
