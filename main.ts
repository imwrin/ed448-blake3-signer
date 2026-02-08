// deno-lint-ignore-file ban-types

// TypeScript implementation of ed448-based signatures via the decaf
// abstraction, with hedged nonces and blake3 for fast hashing. Note that
// JavaScript cannot truly be constant-time due to JIT optimizations,
// for instance, but this is a best-effort attempt to achieve algorithmic
// constant-timeness.
//
// DO NOT USE THIS IN PRODUCTION!

import { randomBytes } from "@noble/hashes/utils.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";
import { decaf448 } from "@noble/curves/ed448.js";
import { add, mod, mult } from "./lib/constant-time/index.ts";
import { cloneBytesConstantTime } from "./lib/utils/index.ts";
import RLP from "rlp";

const CURVE448_SCALAR_BYTE_COUNT = 56;
const CURVE448_POINT_BYTE_COUNT = 56;

const ORDER_BYTES = numberToBytesLE(decaf448.Point.Fn.ORDER, 56);

// & {} forces intellisense to show the entire type
type Signature = { s: Uint8Array; R: Uint8Array } & {};

const SIG_E_HASH_DST =
  "DST:type=signature,curve=curve448-decaf,hash=blake3,nonce=hedged,for=e-hash";

const SIG_NONCE_DST =
  "DST:type=signature,curve=curve448-decaf,hash=blake3,nonce=hedged,for=nonce-hash";

const SIG_DERIVESECRET_DST =
  "DST:type=signature,curve=curve448-decaf,hash=blake3,nonce=hedged,for=derive-secret";

export const createSecret = (order: Uint8Array): Uint8Array => {
  return mod(
    randomBytes(CURVE448_SCALAR_BYTE_COUNT + 32),
    order,
  );
};

/**
 * Derives a secret key from a high-entropy secret value
 * @param secret Secret value to derive a secret key from
 * @param order The order of the curve
 * @returns Uint8Array
 */
export const deriveSecret = (
  secret: Uint8Array,
  order: Uint8Array = ORDER_BYTES,
): Uint8Array => {
  return mod(
    blake3.create({ dkLen: CURVE448_SCALAR_BYTE_COUNT + 32 })
      .update(
        RLP.encode([
          SIG_DERIVESECRET_DST,
          secret,
        ]),
      )
      .digest(),
    order,
  );
};

/**
 * Signs a message
 * @param message The message to the be signed
 * @param secret The secret to sign the message with
 * @param publicKey The public key of the signer
 * @param randomizer The nonce to use
 */
export const sign = (
  message: Uint8Array,
  secret: Uint8Array,
  publicKey?: Uint8Array,
  randomizer?: Uint8Array,
): Signature => {
  // Derive a secret within the scalar field from the secret input
  const derivedSecret = deriveSecret(secret, ORDER_BYTES);

  // If the public key is not provided, derive the public key from the
  // secret key. This is an option provided for the sake of not needing
  // to constantly re-derive the public key for repeated signing
  // operations
  publicKey = publicKey ?? derivePublicKey(derivedSecret);

  const P = publicKey;

  // Check the type of `randomizer` for instantiation instead of the
  // value itself. This in theory should be closer to constant-time.
  const nonceRandomness = (typeof randomizer === 'undefined') ?
    randomBytes(32) :
    cloneBytesConstantTime(randomizer);

  // Generate a hedged nonce
  // k = H(DST || secret || randomness || message)
  const k = mod(
    blake3
      .create({ dkLen: CURVE448_SCALAR_BYTE_COUNT + 32 })
      .update(
        RLP.encode([
          SIG_NONCE_DST,
          derivedSecret,
          nonceRandomness,
          message,
        ]),
      )
      .digest(),
    ORDER_BYTES,
  );

  // R = k.G
  const R = decaf448.Point.BASE.multiply(bytesToNumberLE(k)).toBytes();

  // e = H(DST || R || P || M)
  const e = mod(
    blake3.create({ dkLen: CURVE448_SCALAR_BYTE_COUNT + 32 })
      .update(
        // Use RLP to prevent canonicalization issues. If the length of
        // one of these inputs were to change, say, the DST for instance,
        // RLP prevents issues such as overlapping bytes which may cause
        // subtle canonicalization attacks where different inputs produce
        // the same hash
        RLP.encode([
          SIG_E_HASH_DST,
          R,
          P,
          message,
        ]),
      )
      .digest(),
    ORDER_BYTES,
  );

  // s = k + x * e
  const s = add(
    k,
    mult(
      derivedSecret,
      e,
      ORDER_BYTES,
    ),
    ORDER_BYTES,
  );

  // Best-effort attempt to zero-out non-public data from the RAM
  derivedSecret.fill(0);
  k.fill(0);
  e.fill(0);
  nonceRandomness.fill(0);

  return { s, R };
};

/**
 * Verifies that a signature on a message was produced by a given public key holder
 * @param signature The signature to verify
 * @param message The message to verify the signature against
 * @param publicKey The public key to verify the signature against
 * @returns boolean
 */
export const verifySignature = (
  signature: Signature,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean => {
  try {
    if (
      signature.s.length !== CURVE448_SCALAR_BYTE_COUNT ||
      signature.R.length !== CURVE448_POINT_BYTE_COUNT
    ) return false;

    const R = decaf448.Point.fromBytes(signature.R);
    const P = decaf448.Point.fromBytes(publicKey);

    if (R.equals(decaf448.Point.ZERO) || P.equals(decaf448.Point.ZERO)) {
      return false;
    }

    const signatureBigint = bytesToNumberLE(signature.s);

    if (signatureBigint >= decaf448.Point.Fn.ORDER) return false;

    // e = H(R || M)
    const e = mod(
      blake3
        .create({ dkLen: CURVE448_SCALAR_BYTE_COUNT + 32 })
        .update(
          RLP.encode([
            SIG_E_HASH_DST,
            signature.R,
            publicKey,
            message,
          ]),
        )
        .digest(),
      ORDER_BYTES,
    );

    // The verification point
    // V = s.G
    const V = decaf448.Point.BASE.multiply(signatureBigint);

    // s.G == R + e.P
    const isValid = R
      .add(
        decaf448.Point.fromBytes(publicKey).multiply(bytesToNumberLE(e)),
      )
      .equals(V);

    return isValid;
  } catch {
    return false;
  }
};

export type KeyPair = {
  sk: Uint8Array;
  pk: Uint8Array;
} & {};

/**
 * Derives a public key from a secret key
 * @param sk Secret key to derive the public key from
 * @returns Uint8Array
 */
export const derivePublicKey = (sk: Uint8Array): Uint8Array => {
  return decaf448.Point.BASE.multiply(
    bytesToNumberLE(sk),
  ).toBytes();
};

/**
 * Generates a keypair
 * @returns KeyPair
 */
export const generateKeyPair = (): KeyPair => {
  const sk = createSecret(ORDER_BYTES);

  const pk = derivePublicKey(deriveSecret(sk, ORDER_BYTES));

  return {
    sk,
    pk,
  };
};