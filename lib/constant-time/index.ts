/**
 * Arithmetically Constant-Time Math Library
 */

const BYTE_MASK = 0xFF;

/**
 * Constant-Time Modular Addition
 * Calculates: (a + b) % m
 */
export function add(a: Uint8Array, b: Uint8Array, m: Uint8Array): Uint8Array {
    if (a.length !== m.length || b.length !== m.length) {
        throw new Error("Inputs must have the same length as modulus");
    }

    const len = m.length;
    const res = new Uint8Array(len);
    
    let sumCarry = 0;
    for (let i = 0; i < len; i++) {
        const sum = a[i] + b[i] + sumCarry;
        res[i] = sum & BYTE_MASK;
        sumCarry = sum >>> 8;
    }

    let subBorrow = 0;
    for (let i = 0; i < len; i++) {
        const diff = res[i] - m[i] - subBorrow;
        subBorrow = (diff >>> 8) & 1;
    }

    const keep = (1 - sumCarry) & subBorrow;
    
    const keepMask = -keep; 
    const subMask = ~keepMask;

    let applyBorrow = 0;
    for (let i = 0; i < len; i++) {
        const valRes = res[i];
        
        const diff = valRes - m[i] - applyBorrow;
        applyBorrow = (diff >>> 8) & 1;
        const valDiff = diff & BYTE_MASK;
        
        res[i] = (valRes & keepMask) | (valDiff & subMask);
    }

    return res;
}

/**
 * Constant-Time Modular Multiplication
 * Calculates: (a * b) % m
 */
export function mult(a: Uint8Array, b: Uint8Array, m: Uint8Array): Uint8Array {
    const product = multPlain(a, b);

    return mod(product, m);
}

/**
 * Constant-Time Modulo (Restoring Division)
 * Calculates: a % m
 */
export function mod(a: Uint8Array, m: Uint8Array): Uint8Array {
    const mLen = m.length;
    
    const run = new Uint8Array(mLen); 
    const temp = new Uint8Array(mLen);
    
    const totalBits = a.length * 8;
    
    for (let i = totalBits - 1; i >= 0; i--) {
        const byteIdx = i >>> 3;
        const bitIdx = i & 7;
        const inputBit = (a[byteIdx] >>> bitIdx) & 1;
        
        let carry = inputBit;
        for (let j = 0; j < mLen; j++) {
            const val = run[j];
            const nextCarry = val >>> 7;
            run[j] = ((val << 1) | carry) & BYTE_MASK;
            carry = nextCarry;
        }
        
        const runOverflow = carry;

        let subBorrow = 0;
        for (let j = 0; j < mLen; j++) {
            const diff = run[j] - m[j] - subBorrow;
            temp[j] = diff & BYTE_MASK;
            subBorrow = (diff >>> 8) & 1;
        }

        const swap = runOverflow | (1 ^ subBorrow);
        
        const swapMask = -swap; 
        const keepMask = ~swapMask;

        for (let j = 0; j < mLen; j++) {
            run[j] = (temp[j] & swapMask) | (run[j] & keepMask);
        }
    }

    return run;
}

/**
 * Plain Multiplication (Helper)
 * Returns Uint8Array of size a.length + b.length
 */
function multPlain(a: Uint8Array, b: Uint8Array): Uint8Array {
    const lenA = a.length;
    const lenB = b.length;
    const res = new Uint8Array(lenA + lenB);
    const acc = new Int32Array(res.length);

    for (let i = 0; i < lenA; i++) {
        for (let j = 0; j < lenB; j++) {
            acc[i + j] += a[i] * b[j];
        }
    }

    // Ripple Carry
    let carry = 0;
    for (let i = 0; i < acc.length; i++) {
        const val = acc[i] + carry;
        res[i] = val & BYTE_MASK;
        carry = val >>> 8; 
    }

    return res;
}