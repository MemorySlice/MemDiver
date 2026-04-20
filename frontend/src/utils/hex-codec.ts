const HEX_CHARS = "0123456789abcdef";

export function decodeBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function byteToHex(b: number): string {
  return HEX_CHARS[b >> 4] + HEX_CHARS[b & 0xf];
}

export function byteToAscii(b: number): string {
  return b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
}

export function offsetToHex(offset: number): string {
  return offset.toString(16).padStart(8, "0");
}
