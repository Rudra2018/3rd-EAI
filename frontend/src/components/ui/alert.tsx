import React from "react";
export function Alert({ className = "", ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={`rounded-2xl border border-amber-300 bg-amber-50 p-4 ${className}`} {...props} />;
}
export function AlertTitle({ className = "", ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h4 className={`mb-1 text-sm font-semibold ${className}`} {...props} />;
}
export function AlertDescription({ className = "", ...props }: React.HTMLAttributes<HTMLParagraphElement>) {
  return <p className={`text-sm text-amber-800 ${className}`} {...props} />;
}
