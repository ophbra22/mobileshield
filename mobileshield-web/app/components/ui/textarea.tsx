import React from 'react';
import { twMerge } from 'tailwind-merge';

export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => <textarea ref={ref} className={twMerge('message-input', className)} {...props} />
);
Textarea.displayName = 'Textarea';
