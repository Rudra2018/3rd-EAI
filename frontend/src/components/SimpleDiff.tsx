import React from "react";

function toLines(value: unknown): string[] {
  if (typeof value === "string") {
    try { const parsed = JSON.parse(value); return JSON.stringify(parsed, null, 2).split("\n"); }
    catch { return value.split("\n"); }
  }
  try { return JSON.stringify(value, null, 2).split("\n"); } catch { return String(value).split("\n"); }
}

type Props = { oldValue: unknown; newValue: unknown; className?: string };
export function SimpleDiff({ oldValue, newValue, className = "" }: Props) {
  const left = toLines(oldValue);
  const right = toLines(newValue);
  const max = Math.max(left.length, right.length);
  return (
    <div className={`grid grid-cols-2 gap-3 text-sm ${className}`}>
      {[...Array(max)].map((_, i) => {
        const l = left[i] ?? "";
        const r = right[i] ?? "";
        const changed = l !== r;
        return (
          <React.Fragment key={i}>
            <pre className={`rounded-xl border p-2 font-mono leading-5 ${changed ? "bg-red-50" : "bg-gray-50"}`}>
              <span className="mr-2 text-gray-400">{String(i + 1).padStart(3, " ")}</span>{l}
            </pre>
            <pre className={`rounded-xl border p-2 font-mono leading-5 ${changed ? "bg-green-50" : "bg-gray-50"}`}>
              <span className="mr-2 text-gray-400">{String(i + 1).padStart(3, " ")}</span>{r}
            </pre>
          </React.Fragment>
        );
      })}
    </div>
  );
}
