const FNV_OFFSET = 0x811c9dc5;
const FNV_PRIME = 0x01000193;

export function stableToken(type: string, value: string, salt = ""): string {
  let hash = FNV_OFFSET;
  const input = `${salt}:${type}:${value}`;

  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, FNV_PRIME) >>> 0;
  }

  return `[${type.toUpperCase()}:${hash.toString(16).padStart(8, "0")}]`;
}
