import React from "react";
function Svg(props: React.SVGProps<SVGSVGElement>) {
  const { className = "h-4 w-4", ...rest } = props;
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className={className} {...rest} />;
}
export const Loader2 = (p: React.SVGProps<SVGSVGElement>) => (
  <Svg {...p} className={`animate-spin ${p.className || "h-4 w-4"}`}>
    <circle cx="12" cy="12" r="9" strokeOpacity="0.3" />
    <path d="M21 12a9 9 0 0 0-9-9" strokeLinecap="round" />
  </Svg>
);
export const Upload = (p: React.SVGProps<SVGSVGElement>) => (
  <Svg {...p}><path d="M12 16V4M7 9l5-5 5 5"/><path d="M20 16v2a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-2"/></Svg>
);
export const ShieldCheck = (p: React.SVGProps<SVGSVGElement>) => (
  <Svg {...p}><path d="M12 3l8 4v5a8 8 0 1 1-16 0V7l8-4"/><path d="M9 12l2 2 4-4"/></Svg>
);
export const Bug = (p: React.SVGProps<SVGSVGElement>) => (
  <Svg {...p}><circle cx="12" cy="12" r="3"/><path d="M4 12h4m8 0h4M6 6l3 3m9-3l-3 3M6 18l3-3m9 3l-3-3M12 5v2m0 10v2"/></Svg>
);
export const ExternalLink = (p: React.SVGProps<SVGSVGElement>) => (
  <Svg {...p}><path d="M14 3h7v7"/><path d="M21 3l-9 9"/><path d="M5 12v7a2 2 0 0 0 2 2h7"/></Svg>
);
export const Diff = (p: React.SVGProps<SVGSVGElement>) => (
  <Svg {...p}><path d="M8 3h8v8H8z"/><path d="M3 13h8v8H3z"/><path d="M13 13h8v8h-8z"/></Svg>
);
export const ListFilter = (p: React.SVGProps<SVGSVGElement>) => (
  <Svg {...p}><path d="M3 6h18M6 12h12M10 18h4"/></Svg>
);
export const Link2 = (p: React.SVGProps<SVGSVGElement>) => (
  <Svg {...p}><path d="M10 13a5 5 0 0 1 0-7l1-1a5 5 0 0 1 7 7l-1 1"/><path d="M14 11a5 5 0 0 1 0 7l-1 1a5 5 0 0 1-7-7l1-1"/></Svg>
);
export const Database = (p: React.SVGProps<SVGSVGElement>) => (
  <Svg {...p}><ellipse cx="12" cy="5" rx="7" ry="3"/><path d="M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5"/><path d="M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6"/></Svg>
);
