/**
 * ErrorState — displays a fixed safe error message.
 *
 * Never renders raw response bodies, exception repr, stack traces,
 * temp paths, or credential-like content. The message passed in is
 * always a pre-sanitized fixed string from error-messages.ts or the
 * backend's desensitized error_message field.
 */

interface ErrorStateProps {
  message: string;
}

export function ErrorState({ message }: ErrorStateProps) {
  return (
    <div className="error-box" role="alert">
      {message}
    </div>
  );
}
