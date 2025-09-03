// card.tsx
import React from 'react';
import { twMerge } from 'tailwind-merge';

export function Card({ className, ...props }: React.ComponentPropsWithoutRef<'div'>) {
  return (
    <div
      className={twMerge(
        'bg-white rounded-lg shadow-sm border border-gray-200 dark:bg-gray-800 dark:border-gray-700',
        className
      )}
      {...props}
    />
  );
}
