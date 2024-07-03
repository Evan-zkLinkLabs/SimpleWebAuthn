import { decodeAttestationObject } from "../helpers/decodeAttestationObject.ts";
import { parseAuthenticatorData } from "../helpers/parseAuthenticatorData.ts";
import { decodeCredentialPublicKey } from "../helpers/decodeCredentialPublicKey.ts";
import EC from "elliptic";
import { COSEKEYS, COSEPublicKey } from "../helpers/cose.ts";
import { toHash } from "../helpers/toHash.ts";
import { isoBase64URL, isoUint8Array } from "../helpers/iso/index.ts";

//public key
const _attestationObject =
  "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAPv8MAcVTk7MjAtuAgVX170AFDSFEhZjeUn4KUGDqRONaW1hI1pOpQECAyYgASFYIG4zS41BTIe0sAKJX-P_syiI_VbOexcrLA_AG4-Zc9ecIlgglT_dXqHmBkVKdV-DfSh05YqY7_HTqbhzf1KGUl5B-QY";
const _publicKey =
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAiIegNp0Cv4zCjAd1z-AxjA7n_8vGLmur2Oxvp4xoahArrnNylna_hFiVwKRT41GOgyw6PYZiNBOdJvHPUCoMw";

const attestationObject = isoBase64URL.toBuffer(_attestationObject);
const decodedAttestationObject = decodeAttestationObject(attestationObject);
const authData = decodedAttestationObject.get("authData");

const parsedAuthData = parseAuthenticatorData(authData);
const {
  aaguid,
  rpIdHash,
  flags,
  credentialID,
  counter,
  credentialPublicKey,
  extensionsData,
} = parsedAuthData;

let cosePublicKey: COSEPublicKey = new Map();
cosePublicKey = decodeCredentialPublicKey(credentialPublicKey!);

const x = cosePublicKey.get(COSEKEYS.x);
const y = cosePublicKey.get(COSEKEYS.y);

const ec = EC.ec("p256");
const key = ec.keyFromPublic({ x, y }, "hex");
console.log("isPublicKey Valid", key.validate());

async function verify(data: {
  signature: string;
  authData: string;
  clientData: string;
}) {
  const clientDataHash = await toHash(isoBase64URL.toBuffer(data.clientData));
  const signatureBase = isoUint8Array.concat([
    isoBase64URL.toBuffer(data.authData),
    clientDataHash,
  ]);

  const hash = await toHash(signatureBase);
  const result = key.verify(hash, isoBase64URL.toBuffer(data.signature));
  console.log("signature verify->>>", result);
}

const s1 = {
  signature:
    "MEQCIHBw3VOOLugLKWN8c3yvVHzRPpUOG5b8HMYOh-TCq_9GAiBsBkvOhCYkQOyf721yE9aWaqU0mhvK69YFWAUwygCx0g",
  authData: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
  clientData:
    "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoieDF3UnVTaHlJNGs3QnFZSmk2MGtWay1jbEpXc1BuQkdnaF83ei1XOVFZayIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9",
};

verify(s1);

const s2 = {
  signature:
    "MEUCIAcZYQjX4eLltBc6nzIrTVkFemPNbPI_A8uBNbSpBX_rAiEAvDPusbg8Jffuqfq36IA8x02mwU2dfdLm9iKvhMe5mUU",
  authData: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
  clientData:
    "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQjF3UnVTaHlJNGs3QnFZSmk2MGtWay1jbEpXc1BuQkdnaF83ei1XOVFZayIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
};

verify(s2);
