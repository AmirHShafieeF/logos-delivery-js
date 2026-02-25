import * as secp from "@noble/secp256k1";
import { concat, hexToBytes } from "@waku/utils/bytes";
import { createRoutingInfo } from "@waku/utils";

import { createDecoder } from "./ecies.js";
import { getSubtle, sha256, randomBytes, getPublicKey } from "./crypto/utils.js";
import { IProtoMessage } from "@waku/interfaces";

// Helper functions copied from crypto/ecies.ts since they are not exported

function kdf(secret: Uint8Array, outputLength: number): Promise<Uint8Array> {
  let ctr = 1;
  let written = 0;
  let willBeResult = Promise.resolve(new Uint8Array());
  while (written < outputLength) {
    const counters = new Uint8Array([ctr >> 24, ctr >> 16, ctr >> 8, ctr]);
    const countersSecret = concat(
      [counters, secret],
      counters.length + secret.length
    );
    const willBeHashResult = sha256(countersSecret);
    willBeResult = willBeResult.then((result) =>
      willBeHashResult.then((hashResult) => {
        const _hashResult = new Uint8Array(hashResult);
        return concat(
          [result, _hashResult],
          result.length + _hashResult.length
        );
      })
    );
    written += 32;
    ctr += 1;
  }
  return willBeResult;
}

function aesCtrEncrypt(
  counter: Uint8Array,
  key: ArrayBufferLike,
  data: ArrayBufferLike
): Promise<Uint8Array> {
  return getSubtle()
    .importKey("raw", key, "AES-CTR", false, ["encrypt"])
    .then((cryptoKey) =>
      getSubtle().encrypt(
        { name: "AES-CTR", counter: counter, length: 128 },
        cryptoKey,
        data
      )
    )
    .then((bytes) => new Uint8Array(bytes));
}

function hmacSha256Sign(
  key: ArrayBufferLike,
  msg: ArrayBufferLike
): PromiseLike<Uint8Array> {
  const algorithm = { name: "HMAC", hash: { name: "SHA-256" } };
  return getSubtle()
    .importKey("raw", key, algorithm, false, ["sign"])
    .then((cryptoKey) => getSubtle().sign(algorithm, cryptoKey, msg))
    .then((bytes) => new Uint8Array(bytes));
}

function derive(privateKeyA: Uint8Array, publicKeyB: Uint8Array): Uint8Array {
    const px = secp.getSharedSecret(privateKeyA, publicKeyB, true);
    // Remove the compression prefix
    return new Uint8Array(hexToBytes(px).slice(1));
}

async function maliciousEncrypt(
  publicKeyTo: Uint8Array,
  msg: Uint8Array
): Promise<Uint8Array> {
  const ephemPrivateKey = randomBytes(32);
  const ephemPublicKey = secp.getPublicKey(ephemPrivateKey, false);

  const sharedPx = derive(ephemPrivateKey, publicKeyTo);

  const hash = await kdf(sharedPx, 32);

  const iv = randomBytes(16);
  const encryptionKey = hash.slice(0, 16);
  const cipherText = await aesCtrEncrypt(iv, encryptionKey, msg);

  const ivCipherText = concat([iv, cipherText], iv.length + cipherText.length);

  const macKey = await sha256(hash.slice(16));
  const hmac = await hmacSha256Sign(macKey, ivCipherText);

  return concat(
    [ephemPublicKey, ivCipherText, hmac],
    ephemPublicKey.length + ivCipherText.length + hmac.length
  );
}

const testContentTopic = "/js-waku/1/tests/crash";
const testRoutingInfo = createRoutingInfo(
  {
    clusterId: 0,
    numShardsInCluster: 14
  },
  { contentTopic: testContentTopic }
);

describe("Vulnerability Reproduction: postCipher Crash", function () {
  it("Should NOT crash when decoding a malicious ECIES message", async function () {
    const receiverPrivateKey = randomBytes(32);
    const receiverPublicKey = getPublicKey(receiverPrivateKey);

    // Malicious payload:
    // 0x05:
    //   Size of size field (2 bits) = 0x01 (1 byte)
    //   Signed flag (1 bit) = 1 (IsSigned)
    const maliciousPayload = new Uint8Array([0x05]);

    const encryptedMessage = await maliciousEncrypt(receiverPublicKey, maliciousPayload);

    const decoder = createDecoder(
        testContentTopic,
        testRoutingInfo,
        receiverPrivateKey
    );

    const protoMessage: IProtoMessage = {
        payload: encryptedMessage,
        version: 1,
        contentTopic: testContentTopic,
        timestamp: BigInt(Date.now()) * BigInt(1000000),
        ephemeral: false,
        meta: undefined,
        rateLimitProof: undefined
    };

    // This should NOT throw if fixed.
    // If vulnerable, this will throw RangeError and fail the test.
    await decoder.fromProtoObj(testRoutingInfo.pubsubTopic, protoMessage);
  });
});
