// button.tsx
import React from 'react';
import { twMerge } from 'tailwind-merge';

export function Button({ className, ...props }: React.ComponentPropsWithoutRef<'button'>) {
  return (
    <button
      className={twMerge(
        'bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2',
        className
      )}
      {...props}
    />
  );
}
