import React from 'react';

export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => <textarea ref={ref} className={className ? `message-input ${className}` : 'message-input'} {...props} />
);
Textarea.displayName = 'Textarea';
