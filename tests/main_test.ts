import { assertEquals, assert } from "@std/assert";
import { decaf448 } from "@noble/curves/ed448.js";
import { numberToBytesLE, bytesToNumberLE } from "@noble/curves/utils.js";
import { blake3 } from "@noble/hashes/blake3.js";
import RLP from "rlp"; 
import { 
  generateKeyPair, 
  sign, 
  verifySignature, 
  derivePublicKey, 
  deriveSecret     
} from "../main.ts";
import { GOLDEN_VECTORS } from "./utils/golden-vectors.ts";

const msg = (str: string) => new TextEncoder().encode(str);

const ORDER = decaf448.Point.Fn.ORDER;
const ORDER_BYTES = numberToBytesLE(ORDER, 56);


const DST = {
  NONCE: "DST:type=signature,curve=curve448-decaf,hash=blake3,nonce=hedged,for=nonce-hash",
  E:     "DST:type=signature,curve=curve448-decaf,hash=blake3,nonce=hedged,for=e-hash",
};


Deno.test("Regression: Golden Vector (Full Protocol)", () => {
  GOLDEN_VECTORS.forEach((vector) => {
    // Verify Verification Logic
    assert(verifySignature(vector.sig, vector.msg, vector.pk), "Golden Vector verify failed");

    // Verify key derivation logic
    const derivedScalar = deriveSecret(vector.sk, ORDER_BYTES);
    const derivedPk = derivePublicKey(derivedScalar);
    
    assertEquals(derivedPk, vector.pk, "Key derivation logic is not functioning as expected");
  });
});

Deno.test("Internals: Math Model Validation", () => {
  const { sk, pk } = generateKeyPair();
  const message = msg("Math Check");
  const fixedRandomizer = new Uint8Array(32).fill(0x55);

  const sig = sign(message, sk, pk, fixedRandomizer);

  // Perform Manual Calculation
  // Derive Secret Scalar x
  const xBytes = deriveSecret(sk, ORDER_BYTES);
  const x = bytesToNumberLE(xBytes);

  // Calculate Nonce Scalar k
  const kHash = blake3.create({ dkLen: 88 })
    .update(RLP.encode([DST.NONCE, xBytes, fixedRandomizer, message]))
    .digest();
  const k = bytesToNumberLE(kHash) % ORDER;
  
  // Calculate Nonce Point R
  const R_point = decaf448.Point.BASE.multiply(k);
  const R_bytes = R_point.toBytes();
  
  assertEquals(sig.R, R_bytes, "Math Failure: Nonce Point R mismatch");

  // Calculate Challenge e
  const eHash = blake3.create({ dkLen: 88 })
    .update(RLP.encode([DST.E, R_bytes, pk, message]))
    .digest();
  const e = bytesToNumberLE(eHash) % ORDER;

  // Calculate Signature Scalar s
  // s = k + x * e  (mod L)
  const s = (k + (x * e)) % ORDER;
  const sBytes = numberToBytesLE(s, 56);

  assertEquals(sig.s, sBytes, "Math Failure: Scalar s mismatch");
});

Deno.test("Internals: Scalar Constraints", () => {
  // Verify that inputs to derivePublicKey are always valid when processed correctly
  
  for (let i = 0; i < 50; i++) {
    const sk = new Uint8Array(56);
    crypto.getRandomValues(sk); 

    const scalarBytes = deriveSecret(sk, ORDER_BYTES);
    const scalarFn = bytesToNumberLE(scalarBytes);

    // Check Range
    assert(scalarFn < ORDER, "Derived secret scalar must be < Curve Order");

    // Check Point Correspondence
    // derivedPK == scalar * G
    const expectedPk = decaf448.Point.BASE.multiply(scalarFn).toBytes();
    const actualPk = derivePublicKey(scalarBytes); 
    
    assertEquals(actualPk, expectedPk, "derivePublicKey must match Base * Scalar");
  }
});

Deno.test("Stability: Deterministic Signing (Fixed Randomizer)", () => {
  const { sk, pk } = generateKeyPair();
  const message = msg("Deterministic Test");
  const fixedRandomizer = new Uint8Array(32).fill(0x42); 

  const sig1 = sign(message, sk, pk, fixedRandomizer);
  const sig2 = sign(message, sk, pk, fixedRandomizer);

  assertEquals(sig1.s, sig2.s, "S should be identical");
  assertEquals(sig1.R, sig2.R, "R should be identical");
});

Deno.test("Protocol: Domain Separation & Binding", () => {
  const { sk, pk } = generateKeyPair();
  const message = msg("Example Message 123");
  const signature = sign(message, sk, pk);

  assert(verifySignature(signature, message, pk));
  assert(!verifySignature(signature, msg("Example MessagE 123"), pk));
});

Deno.test("Security: Signature Malleability & Strictness", async (t) => {
  const { sk, pk } = generateKeyPair();
  const validSig = sign(msg("Strictness"), sk, pk);

  await t.step("Reject Truncated", () => {
    const shortS = { s: validSig.s.slice(0, 55), R: validSig.R };
    assert(!verifySignature(shortS, msg("Strictness"), pk));
  });

  await t.step("Reject Padded (Serialization)", () => {
    const longS = new Uint8Array(57);
    longS.set(validSig.s);
    const longSig = { s: longS, R: validSig.R };
    assert(!verifySignature(longSig, msg("Strictness"), pk));
  });
});

Deno.test("Security: Garbage Inputs", () => {
  const { sk, pk } = generateKeyPair();
  const message = msg("Garbage");
  const validSig = sign(message, sk, pk);
  
  const garbageR = new Uint8Array(56).fill(1); 
  try {
    const result = verifySignature({ s: validSig.s, R: garbageR }, message, pk);
    assert(result === false, "Garbage R should return false");
  } catch (e) {
    assert(false, `Verify threw error: ${e}`);
  }
});