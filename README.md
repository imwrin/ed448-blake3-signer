# ed448-blake3-signer
TypeScript implementation of ed448-based signatures via the decaf abstraction, with hedged nonces and blake3 for fast hashing. Note that JavaScript cannot truly be constant-time due to JIT optimizations, for instance, but this is a best-effort attempt to achieve algorithmic constant-timeness.

DO NOT USE THIS IN PRODUCTION!

## Specification

```
type Signature = { s: Uint8Array; R: Uint8Array; }

type KeyPair = { sk: Uint8Array; pk: Uint8Array; }

deriveSecret(secret: Uint8Array, order: Uint8Array) -> Uint8Array

derivePublicKey(secret: Uint8Array) -> Uint8Array

sign(message: Uint8Array, secret: Uint8Array, publicKey?: Uint8Array, randomizer?: Uint8Array) -> Signature

verifySignature(signature: Signature, message: Uint8Array, publicKey: Uint8Array) -> boolean

generateKeyPair() -> KeyPair

createSecret(order: Uint8Array) -> Uint8Array
```