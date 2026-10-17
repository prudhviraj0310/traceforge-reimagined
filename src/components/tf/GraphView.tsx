import { COLUMNS, EDGES, NODES, TYPE_LABEL, type GNode } from "@/lib/traceforge-data";
import { cn } from "@/lib/utils";

const W = 900;
const H = 520;
const PAD_X = 60;
const TOP = 70;

const pos = (() => {
  const m = new Map<string, { x: number; y: number }>();
  COLUMNS.forEach((t, ci) => {
    const col = NODES.filter((n) => n.type === t);
    const x = PAD_X + (ci * (W - PAD_X * 2)) / (COLUMNS.length - 1);
    const gap = (H - TOP - 50) / Math.max(col.length, 1);
    col.forEach((n, i) => m.set(n.id, { x, y: TOP + gap * (i + 0.5) + 10 }));
  });
  return m;
})();

interface Props {
  path: string[];
  revealed: number;
  choke?: string | null;
  severed?: boolean;
  selected: string | null;
  onSelect: (id: string) => void;
}

export function GraphView({ path, revealed, choke, severed, selected, onSelect }: Props) {

  const visible = path.slice(0, revealed);
  const onPath = (id: string) => visible.includes(id);
  const edgeOnPath = (s: string, t: string) => {
    const i = visible.indexOf(s);
    return i >= 0 && visible[i + 1] === t;
  };
  const active = revealed > 0;

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full" role="img" aria-label="Infrastructure graph">
      {COLUMNS.map((t, ci) => {
        const x = PAD_X + (ci * (W - PAD_X * 2)) / (COLUMNS.length - 1);
        return (
          <text key={t} x={x} y={28} textAnchor="middle" className="fill-muted-foreground text-[11px] font-semibold uppercase tracking-[0.14em]">
            {TYPE_LABEL[t]}
          </text>
        );
      })}
      {EDGES.map((e) => {
        const a = pos.get(e.source)!;
        const b = pos.get(e.target)!;
        const hot = edgeOnPath(e.source, e.target);
        const cut = severed && hot && e.source === choke;
        const mx = (a.x + b.x) / 2;
        return (
          <path
            key={e.source + e.target}
            d={`M${a.x},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x},${b.y}`}
            fill="none"
            className={cn(
              "transition-all duration-500",
              hot ? (cut ? "stroke-muted-foreground/40" : "stroke-accent flow-dash") : active ? "stroke-border" : "stroke-foreground/15",
            )}
            strokeWidth={hot ? 2.5 : 1.25}
          />
        );
      })}
      {NODES.map((n) => (
        <Node
          key={n.id}
          n={n}
          p={pos.get(n.id)!}
          hot={onPath(n.id)}
          dim={active && !onPath(n.id)}
          isChoke={choke === n.id && revealed >= path.length}
          severed={!!severed}
          selected={selected === n.id}
          onSelect={onSelect}
        />
      ))}
    </svg>
  );
}

function Node({ n, p, hot, dim, isChoke, severed, selected, onSelect }: {
  n: GNode; p: { x: number; y: number }; hot: boolean; dim: boolean; isChoke: boolean; severed: boolean; selected: boolean; onSelect: (id: string) => void;
}) {
  const jewel = !!n.props["crown_jewel"];
  return (
    <g
      transform={`translate(${p.x},${p.y})`}
      onClick={() => onSelect(n.id)}
      className={cn("cursor-pointer transition-opacity duration-500", dim && "opacity-35")}
    >
      {isChoke && <circle r={24} className={cn("fill-none stroke-accent", severed ? "opacity-30" : "animate-pulse")} strokeWidth={1.5} strokeDasharray="3 3" />}
      {selected && <circle r={20} className="fill-none stroke-foreground" strokeWidth={1.5} />}
      <circle
        r={hot ? 13 : 10}
        className={cn(
          "transition-all duration-500",
          hot ? "fill-foreground" : jewel ? "fill-secondary stroke-gold" : "fill-card stroke-foreground/50",
        )}
        strokeWidth={hot ? 0 : 1.5}
      />
      {hot && <circle r={4} className="fill-accent" />}
      {jewel && !hot && <circle r={3.5} className="fill-gold" />}
      <text y={hot ? 32 : 28} textAnchor="middle" className={cn("text-[10.5px]", hot ? "fill-foreground font-semibold" : "fill-muted-foreground")}>
        {n.name}
      </text>
    </g>
  );
}
