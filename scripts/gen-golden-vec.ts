import { parseArgs } from "@std/cli/parse-args";
import { generateKeyPair, sign } from "../main.ts";

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

/**
 * Generates a golden vector for regression testing.
 * @param inputMsg The message string to be signed.
 */
export const generateGoldenVector = (inputMsg: string) => {
  const { sk, pk } = generateKeyPair();

  const message = new TextEncoder().encode(inputMsg);

  const signature = sign(message, sk, pk);

  console.log('\n');
  console.log(`{`);
  console.log(`  sk: hex("${bytesToHex(sk)}"),`);
  console.log(`  pk: hex("${bytesToHex(pk)}"),`);
  console.log(`  msg: msg("${inputMsg}"),`);
  console.log(`  sig: {`);
  console.log(`    s: hex("${bytesToHex(signature.s)}"),`);
  console.log(`    R: hex("${bytesToHex(signature.R)}")`);
  console.log(`  }`);
  console.log(`};`);
  console.log(`\n`);
};

if (import.meta.main) {
  const args = parseArgs(Deno.args, {
    string: ["msg"],
    default: { msg: "Golden Vector Test" },
  });

  generateGoldenVector(args.msg);
}