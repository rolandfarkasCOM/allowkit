const encoder = new TextEncoder();

export async function hashWithSalt(value: string, salt: string): Promise<string> {
  const data = encoder.encode(`${salt}:${value}`);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(digest));
}

// Salt-less SHA-256 hex — used for idempotency body-binding where we want a
// canonical hash of the request body that the client can also compute without
// any server secret.
export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value));
  return bytesToHex(new Uint8Array(digest));
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}
