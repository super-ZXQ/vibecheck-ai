/**
 * ErrorState — displays a fixed safe error message.
 *
 * Never renders raw response bodies, exception repr, stack traces,
 * temp paths, or credential-like content. The message passed in is
 * always a pre-sanitized fixed string or a desensitized failed-task
 * status message.
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
