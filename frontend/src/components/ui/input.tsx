// input.tsx
import React from 'react';
import { twMerge } from 'tailwind-merge';

export function Input({ className, ...props }: React.ComponentPropsWithoutRef<'input'>) {
  return (
    <input
      className={twMerge(
        'w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 dark:bg-gray-700 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent',
        className
      )}
      {...props}
    />
  );
}
