import React, { ReactNode } from "react";
type TabsProps = { value: string; onValueChange?: (v: string) => void; className?: string; children: ReactNode };
type TabsListProps = { className?: string; children: ReactNode };
type TabsTriggerProps = { value: string; current: string; onSelect: (v: string) => void; children: ReactNode };
type TabsContentProps = { value: string; current: string; children: ReactNode };

export function Tabs({ value, onValueChange, className = "", children }: TabsProps) {
  return <div className={className} data-value={value} data-onchange={!!onValueChange}>{children}</div>;
}
export function TabsList({ className = "", children }: TabsListProps) {
  return <div className={`mb-3 inline-flex rounded-xl border p-1 ${className}`}>{children}</div>;
}
export function TabsTrigger({ value, current, onSelect, children }: TabsTriggerProps) {
  const active = value === current;
  return (
    <button
      type="button"
      onClick={() => onSelect(value)}
      className={`rounded-lg px-3 py-1.5 text-sm ${active ? "bg-black text-white" : "text-gray-600 hover:bg-gray-100"}`}
    >
      {children}
    </button>
  );
}
export function TabsContent({ value, current, children }: TabsContentProps) {
  if (value !== current) return null;
  return <div>{children}</div>;
}
