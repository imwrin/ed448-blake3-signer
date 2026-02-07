/**
 * Copies a Uint8Array in a way that minimizes data-dependent timing differences.
 */
export const cloneBytesConstantTime = (source: Uint8Array): Uint8Array => {
  const copy = new Uint8Array(source.length);
  for (let i = 0; i < source.length; i++) {
    copy[i] = source[i];
  }
  return copy;
};