/**
 * Utility helpers to format dates and timestamps into Indian Standard Time (IST - Asia/Kolkata).
 */

export function formatToIST(timestamp: string | Date | undefined | null): string {
  if (!timestamp) return '—';
  const str = typeof timestamp === 'string' ? timestamp : timestamp.toISOString();
  // Ensure UTC indicator if no timezone offset is present
  const utcStr = str.endsWith('Z') || str.includes('+') ? str : `${str}Z`;

  try {
    const date = new Date(utcStr);
    return (
      date.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true,
      }) + ' IST'
    );
  } catch {
    return str;
  }
}

export function formatDateToIST(timestamp: string | Date | undefined | null): string {
  if (!timestamp) return '—';
  const str = typeof timestamp === 'string' ? timestamp : timestamp.toISOString();
  const utcStr = str.endsWith('Z') || str.includes('+') ? str : `${str}Z`;

  try {
    const date = new Date(utcStr);
    return date.toLocaleDateString('en-IN', {
      timeZone: 'Asia/Kolkata',
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return str;
  }
}
