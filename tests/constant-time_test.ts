import { assertEquals, assertThrows } from "@std/assert";
import { add, mult, mod } from "../lib/constant-time/index.ts"; 

function bytesToBigInt(bytes: Uint8Array): bigint {
  let ret = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    ret = (ret << 8n) | BigInt(bytes[i]);
  }
  return ret;
}

function bigIntToBytes(val: bigint, len: number): Uint8Array {
  const ret = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    ret[i] = Number(val & 0xFFn);
    val >>= 8n;
  }
  return ret;
}

function randomBytes(len: number): Uint8Array {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}


Deno.test("Regression: Golden Vectors (Standard Math)", () => {

  const m1 = bigIntToBytes(20n, 1);
  const a1 = bigIntToBytes(5n, 1);
  const b1 = bigIntToBytes(10n, 1);
  assertEquals(bytesToBigInt(add(a1, b1, m1)), 15n, "Basic addition failed");

  const a2 = bigIntToBytes(15n, 1);
  const b2 = bigIntToBytes(10n, 1);
  assertEquals(bytesToBigInt(add(a2, b2, m1)), 5n, "Modular wrap-around failed");

  const a3 = bigIntToBytes(10n, 1);
  assertEquals(bytesToBigInt(add(a3, a3, m1)), 0n, "Exact modulus sum should be 0");
});

Deno.test("Internals: Overflow & Carry Propagation", async (t) => {

  const m = new Uint8Array([0xFB]); 
  
  await t.step("Byte Overflow Logic", () => {
    const a = new Uint8Array([250]);
    const b = new Uint8Array([20]);
    const res = add(a, b, m);
    assertEquals(bytesToBigInt(res), 19n, "Byte overflow carry not handled");
  });

  await t.step("Multi-Limb Carry", () => {
    const m16 = new Uint8Array([0xFF, 0xFF]);
    const a16 = new Uint8Array([0xFF, 0xFF]);
    const b16 = new Uint8Array([0x01, 0x00]);
    
    const res = add(a16, b16, m16);
    assertEquals(bytesToBigInt(res), 1n, "Multi-byte ripple carry failed");
  });
});

Deno.test("Internals: Modular Reduction (Restoring Division)", () => {
  const m = bigIntToBytes(13n, 1);

  const cases = [
    { in: 10n, want: 10n },
    { in: 13n, want: 0n },
    { in: 14n, want: 1n },
    { in: 255n, want: 8n },
    { in: 1000n, want: 12n },
  ];

  cases.forEach((c) => {

    let aLen = 1;
    if (c.in > 255n) aLen = 2;
    
    const a = bigIntToBytes(c.in, aLen);
    const res = mod(a, m);
    
    assertEquals(bytesToBigInt(res), c.want, `Failed mod(${c.in}, 13)`);

    assertEquals(res.length, m.length, "Output length must match modulus");
  });
});

Deno.test("Internals: Multiplication Logic", () => {

  const m = bigIntToBytes(100n, 1);
  const a = bigIntToBytes(10n, 1);
  const b = bigIntToBytes(10n, 1);
  
  const res = mult(a, b, m);
  assertEquals(bytesToBigInt(res), 0n);

  const pVal = 2147483647n;
  const p = bigIntToBytes(pVal, 4);
  
  const x = bigIntToBytes(2000000000n, 4);
  const y = bigIntToBytes(3n, 4);
  
  const expected = (2000000000n * 3n) % pVal;
  
  const resBig = mult(x, y, p);
  assertEquals(bytesToBigInt(resBig), expected, "Large multiplication failed");
});

Deno.test("Stability: Property-Based Fuzzing", async (t) => {
  const NUM_RUNS = 100;
  const BYTE_LEN = 32;

  await t.step(`Fuzzing Add (${NUM_RUNS} runs)`, () => {
    for (let i = 0; i < NUM_RUNS; i++) {
      const mBytes = randomBytes(BYTE_LEN);

      if (mBytes[0] === 0) mBytes[0] = 1; 
      
      const mVal = bytesToBigInt(mBytes);

      let aVal = bytesToBigInt(randomBytes(BYTE_LEN));
      let bVal = bytesToBigInt(randomBytes(BYTE_LEN));
      if (aVal >= mVal) aVal %= mVal;
      if (bVal >= mVal) bVal %= mVal;

      const aBytes = bigIntToBytes(aVal, BYTE_LEN);
      const bBytes = bigIntToBytes(bVal, BYTE_LEN);

      const expected = (aVal + bVal) % mVal;
      const actual = bytesToBigInt(add(aBytes, bBytes, mBytes));

      assertEquals(actual, expected, `Fuzz Add failed on iter ${i}`);
    }
  });

  await t.step(`Fuzzing Mult (${NUM_RUNS} runs)`, () => {
    for (let i = 0; i < NUM_RUNS; i++) {

      const LEN = 4; 
      const mBytes = randomBytes(LEN);
      if (mBytes[0] === 0) mBytes[0] = 1;
      const mVal = bytesToBigInt(mBytes);

      const aBytes = randomBytes(LEN);
      const bBytes = randomBytes(LEN);
      const aVal = bytesToBigInt(aBytes);
      const bVal = bytesToBigInt(bBytes);

      const expected = (aVal * bVal) % mVal;
      const actual = bytesToBigInt(mult(aBytes, bBytes, mBytes));

      assertEquals(actual, expected, `Fuzz Mult failed on iter ${i}`);
    }
  });
});

Deno.test("Security: Input Validation & Constraints", () => {
  const m = new Uint8Array(32).fill(0xFF);
  const a = new Uint8Array(32).fill(0x01);
  const bShort = new Uint8Array(31).fill(0x01);
  const bLong = new Uint8Array(33).fill(0x01);

  assertThrows(() => {
    add(a, bShort, m);
  }, Error, "Inputs must have the same length", "Should reject short inputs");

  assertThrows(() => {
    add(a, bLong, m);
  }, Error, "Inputs must have the same length", "Should reject long inputs");
  try {
    const zeroM = new Uint8Array(4).fill(0);
    const input = new Uint8Array(4).fill(5);
    mod(input, zeroM); 
  } catch {/* */}
});