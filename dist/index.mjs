var __defProp = Object.defineProperty;
var __getOwnPropSymbols = Object.getOwnPropertySymbols;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __propIsEnum = Object.prototype.propertyIsEnumerable;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __spreadValues = (a, b) => {
  for (var prop in b || (b = {}))
    if (__hasOwnProp.call(b, prop))
      __defNormalProp(a, prop, b[prop]);
  if (__getOwnPropSymbols)
    for (var prop of __getOwnPropSymbols(b)) {
      if (__propIsEnum.call(b, prop))
        __defNormalProp(a, prop, b[prop]);
    }
  return a;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/verifiable/credential.ts
import { EcdsaSecp256k1Signature2019 } from "@bloomprotocol/ecdsa-secp256k1-signature-2019";
import { EcdsaSecp256k1VerificationKey2019 as EcdsaSecp256k1VerificationKey20192 } from "@bloomprotocol/ecdsa-secp256k1-verification-key-2019";
import {
  Ed25519Signature2018,
  Ed25519VerificationKey2018 as Ed25519VerificationKey20182
} from "@transmute/ed25519-signature-2018";
import { verifiable } from "@transmute/vc.js";
import Base58 from "bs58";
import { Buffer as Buffer4 } from "buffer";
import _3 from "lodash";

// src/errors/index.ts
var ERRORS = Object.freeze({
  DID_PUBLIC_KEY_MISMATCH: "Did does not match given public key",
  INVALID_DID_ERROR: "Invalid did",
  INVALID_DOCUMENT: "Invalid did document",
  TYPE_NOT_VALID: "Document type not valid",
  NO_ISSUER: "Issuer information is missing",
  NO_ISSUER_DID: "Issuer did is missing",
  INVALID_ISSUER_PUBLIC_KEY: "Issuer public key is not valid",
  INVALID_ISSUER_PRIVATE_KEY: "Issuer private key is not valid",
  NO_HOLDER_PUBLIC_KEY: "Holder public key is missing",
  NO_ISSUER_PUBLIC_KEY: "Issuer public key is missing",
  NO_SUBJECT: "Subject information is missing",
  NO_SUBJECT_DID: "Subject did is missing",
  NO_SUBJECT_PUBLIC_KEY: "Subject public key is missing",
  NO_CLAIMS: "Claim information is missing",
  NO_CREDENTIALS: "Credential information is missing",
  NO_PROOF_VC: "Credential proof is missing",
  NO_PROOF_VP: "Presentation proof is missing",
  MASKING_ERROR: "Masking failed",
  SIGNING_ERROR: "Signing failed",
  INVALID_HOLDER_PRIVATE_KEY: "Holder private key is not valid",
  INVALID_HOLDER_PUBLIC_KEY: "Holder public key is not valid",
  INVALID_VC_PROOF: "VC proof is invalid",
  INVALID_VC_SELECTIVE_DISCLOSURE_PROOF: "VC selective disclosure proof is invalid",
  INVALID_VP_PROOF: "VP proof is invalid",
  INVALID_SIGNATURE: "Proof is invalid",
  UNKNOWN_ERROR: "Unknown error",
  FAILED_MASK_VERIFICATION: "Failed to verify masked verifiable credential",
  NO_VERIFICATION_METHOD: "No verification method found"
});
var errors_default = ERRORS;

// src/functions/index.ts
var functions_exports = {};
__export(functions_exports, {
  base64UrlDecode: () => base64UrlDecode,
  base64UrlEncode: () => base64UrlEncode,
  blind: () => blind,
  checkVcMetaData: () => checkVcMetaData,
  checkVpMetaData: () => checkVpMetaData,
  getFullPrivateKeyBs58: () => getFullPrivateKeyBs58,
  getKeyValue: () => getKeyValue,
  getVerificationKey: () => getVerificationKey,
  privateKeyToDoc: () => privateKeyToDoc,
  sortObject: () => sortObject
});
import * as hashUtils from "hash.js";
import { Ed25519VerificationKey2018 } from "@transmute/ed25519-signature-2018";
import * as secp256k1 from "secp256k1";
import base58 from "bs58";
import { Buffer as Buffer2 } from "buffer";
import _ from "lodash";
import { EcdsaSecp256k1VerificationKey2019 } from "@bloomprotocol/ecdsa-secp256k1-verification-key-2019";
import keccak256 from "keccak256";
function base64UrlEncode(unencoded) {
  return Buffer2.from(unencoded).toString("base64").replace("+", "-").replace("/", "_").replace(/=+$/, "");
}
function base64UrlDecode(encoded) {
  encoded = encoded.replace("-", "+").replace("_", "/");
  while (encoded.length % 4) {
    encoded += "=";
  }
  return Buffer2.from(encoded, "base64").toString("utf8");
}
function blind(data, key) {
  const sha2562 = hashUtils.sha256();
  const blinded = sha2562.update(data + key).digest("hex");
  return blinded;
}
var sortObject = (object) => {
  if (typeof object === "object" && object instanceof Array) {
    object.sort(function(key1, key2) {
      if (key1 < key2) return -1;
      if (key1 > key2) return 1;
      return 0;
    });
    return object;
  }
  const sortedObj = {}, keys = Object.keys(object);
  keys.sort(function(key1, key2) {
    if (key1 < key2) return -1;
    if (key1 > key2) return 1;
    return 0;
  });
  for (const index in keys) {
    const key = keys[index];
    if (typeof object[key] == "object") {
      sortedObj[key] = sortObject(object[key]);
    } else {
      sortedObj[key] = object[key];
    }
  }
  return sortedObj;
};
var privateKeyToDoc = async (privateKey, didMethod = "key") => {
  let publicKey, did;
  const privateKeyBuffer = new Uint8Array(Buffer2.from(privateKey, "hex"));
  if (didMethod == "ethr") {
    const publicKeyBuffer = secp256k1.publicKeyCreate(privateKeyBuffer, false);
    const publicKeyBufferCompressed = secp256k1.publicKeyCreate(privateKeyBuffer, true);
    publicKey = Buffer2.from(publicKeyBufferCompressed).toString("hex");
    const addressBuffer = Buffer2.from(keccak256(Buffer2.from(publicKeyBuffer.slice(1)))).slice(
      -20
    );
    did = `did:ethr:0x${addressBuffer.toString("hex")}`;
  } else {
    const verificationKey = await getVerificationKey({
      seed: privateKey,
      didMethod
    });
    const verificationKeyExport = await verificationKey.export({
      type: "Ed25519VerificationKey2018"
    });
    publicKey = Buffer2.from(base58.decode(verificationKeyExport.publicKeyBase58)).toString(
      "hex"
    );
    did = verificationKey.id.split("#")[0];
  }
  return {
    privateKey,
    publicKey,
    DID: did
  };
};
async function getVerificationKey({
  seed,
  didMethod
}) {
  let key = null;
  if (didMethod === "key") {
    key = await Ed25519VerificationKey2018.generate({
      secureRandom: () => {
        return Buffer2.from(seed, "hex");
      }
    });
  } else if (didMethod === "ethr" || didMethod === "moon") {
    const document = await privateKeyToDoc(seed, didMethod);
    key = await EcdsaSecp256k1VerificationKey2019.generate({
      seed: new Uint8Array(Buffer2.from(seed, "hex")),
      controller: document.DID,
      id: `${document.DID}#owner`
    });
  }
  return key;
}
var checkVcMetaData = (vc) => {
  var _a;
  const { issuer, type, credentialSubject, proof } = vc;
  if (!proof) {
    if (!((_a = credentialSubject == null ? void 0 : credentialSubject.selectiveDisclosureMetaData) == null ? void 0 : _a.proof))
      throw new Error(errors_default.NO_PROOF_VC);
  }
  if (!issuer) {
    throw new Error(errors_default.NO_ISSUER);
  }
  if (!type.includes("VerifiableCredential")) {
    throw new Error(errors_default.TYPE_NOT_VALID);
  }
  if (!credentialSubject) {
    throw new Error(errors_default.NO_CLAIMS);
  }
};
var checkVpMetaData = (vp) => {
  const { holder, verifiableCredential, type, proof } = vp;
  if (!proof) {
    throw new Error(errors_default.NO_PROOF_VC);
  }
  if (!type.includes("VerifiablePresentation")) {
    throw new Error(errors_default.TYPE_NOT_VALID);
  }
  if (!holder) {
    throw new Error(errors_default.NO_SUBJECT_DID);
  }
  if (!verifiableCredential) {
    throw new Error(errors_default.NO_CREDENTIALS);
  } else if (verifiableCredential.length < 1) {
    throw new Error(errors_default.NO_CREDENTIALS);
  }
};
var getKeyValue = (obj, key) => {
  if (!obj) return null;
  for (const k in obj) {
    if (k === key) return obj[k];
    if (_.isObject(obj[k]) && !_.isArray(obj[k])) {
      let v = getKeyValue(obj[k], key);
      if (v) return v;
    }
  }
  return null;
};
var getFullPrivateKeyBs58 = (privateKey, publicKey) => {
  const seed = Buffer2.from(privateKey, "hex");
  const fullIssuerPrivateKey = Buffer2.concat([seed, Buffer2.from(publicKey, "hex")]);
  const privateKeyBase58 = base58.encode(fullIssuerPrivateKey);
  return privateKeyBase58;
};

// src/utils/mask.ts
import _2 from "lodash";
var createMask = ({ mask = {}, credentialSubject = {}, holderPublicKey }) => {
  let maskedClaims = {};
  let maskedMasks = {};
  if (_2.isArray(credentialSubject)) {
    maskedClaims = [];
    for (let key = 0; key < credentialSubject.length; key++) {
      const maskValues = mask == null ? void 0 : mask[key];
      if (maskValues) {
        if (credentialSubject == null ? void 0 : credentialSubject[key]) {
          try {
            const maskedKey = blind(credentialSubject[key], holderPublicKey);
            if (_2.isObject(mask == null ? void 0 : mask[key]) && _2.isObject(credentialSubject[key])) {
              const result = createMask({
                mask: mask == null ? void 0 : mask[key],
                credentialSubject: credentialSubject[key],
                holderPublicKey
              });
              maskedClaims.push(result == null ? void 0 : result.maskedClaims);
              if (_2.size(result == null ? void 0 : result.maskedMasks)) maskedMasks[key] = result == null ? void 0 : result.maskedMasks;
              continue;
            }
            maskedClaims.push(maskedKey);
            maskedMasks[key] = true;
          } catch (error) {
            throw Error(`Masking failed
${error.message}`);
          }
        }
      } else {
        maskedClaims.push(credentialSubject[key]);
      }
    }
  } else if (_2.isObject(credentialSubject)) {
    for (const key in credentialSubject) {
      const maskValues = mask == null ? void 0 : mask[key];
      if (maskValues) {
        const maskedKey = key;
        if (credentialSubject == null ? void 0 : credentialSubject[key]) {
          try {
            if (_2.isObject(mask == null ? void 0 : mask[key]) && _2.isObject(credentialSubject[key])) {
              const result = createMask({
                mask: mask == null ? void 0 : mask[key],
                credentialSubject: credentialSubject[key],
                holderPublicKey
              });
              maskedClaims[maskedKey] = result == null ? void 0 : result.maskedClaims;
              if (_2.size(result == null ? void 0 : result.maskedMasks))
                maskedMasks[maskedKey] = result == null ? void 0 : result.maskedMasks;
              continue;
            }
            maskedClaims[maskedKey] = blind(credentialSubject[key], holderPublicKey);
            maskedMasks[maskedKey] = true;
          } catch (error) {
            throw Error(`Masking failed
${error.message}`);
          }
        }
      } else {
        maskedClaims[key] = credentialSubject[key];
      }
    }
  }
  return {
    maskedClaims: sortObject(maskedClaims),
    maskedMasks: sortObject(maskedMasks)
  };
};
var fullMask = ({ mask = {}, credentialSubject = {}, holderPublicKey }) => {
  let maskedClaims = {};
  let maskedMasks = {};
  if (_2.isArray(credentialSubject)) {
    maskedClaims = [];
    for (let key = 0; key < credentialSubject.length; key++) {
      const maskValues = !(mask == null ? void 0 : mask[key]) || _2.isObject(mask == null ? void 0 : mask[key]);
      if (maskValues) {
        if (credentialSubject == null ? void 0 : credentialSubject[key]) {
          try {
            const maskedKey = key;
            if (_2.isObject(mask == null ? void 0 : mask[key]) && _2.isObject(credentialSubject[key])) {
              const result = fullMask({
                mask: mask == null ? void 0 : mask[key],
                credentialSubject: credentialSubject[key],
                holderPublicKey
              });
              maskedClaims.push(result == null ? void 0 : result.maskedClaims);
              if (_2.size(result == null ? void 0 : result.maskedMasks)) maskedMasks[key] = result == null ? void 0 : result.maskedMasks;
              continue;
            }
            maskedClaims.push(maskedKey);
            maskedMasks[key] = true;
          } catch (error) {
            throw Error(`Masking failed
${error.message}`);
          }
        }
      } else {
        maskedClaims.push(credentialSubject[key]);
      }
    }
  } else if (_2.isObject(credentialSubject)) {
    for (const key in credentialSubject) {
      const maskValues = !(mask == null ? void 0 : mask[key]) || _2.isObject(mask == null ? void 0 : mask[key]);
      if (maskValues) {
        if (credentialSubject == null ? void 0 : credentialSubject[key]) {
          const maskedKey = key;
          try {
            if (_2.isObject(mask == null ? void 0 : mask[key]) && _2.isObject(credentialSubject[key])) {
              const result = fullMask({
                mask: mask == null ? void 0 : mask[key],
                credentialSubject: credentialSubject[key],
                holderPublicKey
              });
              maskedClaims[maskedKey] = result == null ? void 0 : result.maskedClaims;
              if (_2.size(result == null ? void 0 : result.maskedMasks))
                maskedMasks[maskedKey] = result == null ? void 0 : result.maskedMasks;
              continue;
            }
            maskedClaims[maskedKey] = blind(credentialSubject[key], holderPublicKey);
            maskedMasks[maskedKey] = true;
          } catch (error) {
            throw Error(`Masking failed
${error.message}`);
          }
        }
      } else {
        maskedClaims[key] = credentialSubject[key];
      }
    }
  }
  return {
    maskedClaims: sortObject(maskedClaims),
    maskedMasks: sortObject(maskedMasks)
  };
};
var mask_default = { create: createMask, full: fullMask };

// src/utils/signature.ts
import shajs from "sha.js";
import { Buffer as Buffer3 } from "buffer";
import * as secp256k12 from "secp256k1";
var generateKeySignature = ({ data, privateKey }) => {
  const ed = new utils_default.ed25519();
  const privateKeyBuffer = Buffer3.from(privateKey, "hex");
  const dataString = JSON.stringify(data);
  const dataStringHash = new shajs.sha256().update(dataString).digest("hex");
  const dataStringHashBuffer = Buffer3.from(dataStringHash, "hex");
  const signature = ed.sign(dataStringHashBuffer, privateKeyBuffer).toHex();
  return signature;
};
var verifyKeySignature = ({ data, signature, publicKey }) => {
  try {
    const ed = new utils_default.ed25519();
    const vcString = JSON.stringify(data);
    const vcHash = new shajs.sha256().update(vcString).digest("hex");
    const vcHashBuffer = Buffer3.from(vcHash, "hex");
    const result = ed.verify(signature, vcHashBuffer, publicKey);
    if (result === true) return result;
    throw Error(errors_default.FAILED_MASK_VERIFICATION);
  } catch (error) {
    throw Error(errors_default.INVALID_SIGNATURE);
  }
};
var generateEthrSignature = ({ data, privateKey }) => {
  const privateKeyBuffer = Buffer3.from(privateKey, "hex");
  const dataString = JSON.stringify(data);
  const dataStringHash = new shajs.sha256().update(dataString).digest("hex");
  const dataStringHashBuffer = Buffer3.from(dataStringHash, "hex");
  const signature = Buffer3.from(
    secp256k12.ecdsaSign(dataStringHashBuffer, privateKeyBuffer).signature
  ).toString("hex");
  return signature;
};
var verifyEthrSignature = ({ data, signature, publicKey }) => {
  try {
    const vcString = JSON.stringify(data);
    const vcHash = new shajs.sha256().update(vcString).digest("hex");
    const vcHashBuffer = Buffer3.from(vcHash, "hex");
    const dataStringBuffer = new Uint8Array(Buffer3.from(signature, "hex"));
    const publicKeyBuffer = new Uint8Array(Buffer3.from(publicKey, "hex"));
    const result = secp256k12.ecdsaVerify(dataStringBuffer, vcHashBuffer, publicKeyBuffer);
    if (result === true) return result;
    throw Error(errors_default.FAILED_MASK_VERIFICATION);
  } catch (error) {
    throw Error(errors_default.INVALID_SIGNATURE);
  }
};
var signature_default = {
  key: {
    generate: generateKeySignature,
    verify: verifyKeySignature
  },
  ethr: {
    generate: generateEthrSignature,
    verify: verifyEthrSignature
  }
};

// src/utils/ed25519.ts
import { eddsa as EdDSA } from "elliptic";
var Ed25519 = class {
  constructor() {
    this.ed = new EdDSA("ed25519");
  }
  /**
   * sign message with private key
   *
   * @param message - Buffer | Uint8Array
   * @param privateKey - Buffer | Uint8Array
   *
   * @returns - Signed buffer
   */
  sign(message, privateKey) {
    const pvt = this.ed.keyFromSecret(privateKey);
    return pvt.sign(message);
  }
  /**
   * verify message with public key
   *
   * @param signature - Buffer | Uint8Array | Hex
   * @param message - Buffer | Uint8Array
   * @param publicKey - Hex string
   *
   * @returns - boolean
   */
  verify(signature, message, publicKey) {
    const pub = this.ed.keyFromPublic(publicKey, "hex");
    return pub.verify(message, signature);
  }
};

// src/utils/index.ts
import * as secp256k13 from "secp256k1";
var utils_default = { mask: mask_default, signature: signature_default, ed25519: Ed25519, secp256k1: secp256k13 };

// src/verifiable/credential.ts
var create = async ({
  issuerPrivateKey,
  issuanceDate = (/* @__PURE__ */ new Date()).toISOString(),
  documentLoader,
  credential,
  suite = void 0,
  didMethod
}) => {
  var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k, _l, _m, _n, _o, _p, _q, _r, _s;
  try {
    if (!didMethod) {
      didMethod = ((_b = (_a = getKeyValue(credential, "issuer")) == null ? void 0 : _a.split(":")) == null ? void 0 : _b[1]) || "key";
    }
    const { credentialSubject } = credential;
    const holder = getKeyValue(credentialSubject, "holder");
    if (!holder) throw new Error(errors_default.NO_HOLDER_PUBLIC_KEY);
    const documentLoaderResult = await documentLoader(holder);
    let holderPublicKey;
    if ((_c = documentLoaderResult == null ? void 0 : documentLoaderResult.document) == null ? void 0 : _c.verificationMethod) {
      const verificationMethod = (_d = documentLoaderResult == null ? void 0 : documentLoaderResult.document) == null ? void 0 : _d.verificationMethod.filter(
        (vm) => vm.type === "EcdsaSecp256k1VerificationKey2019" || vm.type === "Ed25519VerificationKey2018"
      );
      switch ((_e = verificationMethod[0]) == null ? void 0 : _e.type) {
        case "Ed25519VerificationKey2018":
          holderPublicKey = Buffer4.from(
            Base58.decode((_f = verificationMethod[0]) == null ? void 0 : _f.publicKeyBase58)
          ).toString("hex");
          break;
        case "EcdsaSecp256k1VerificationKey2019":
          holderPublicKey = (_g = verificationMethod[0]) == null ? void 0 : _g.publicKeyHex;
          break;
      }
      if (!holderPublicKey) throw new Error(errors_default.NO_HOLDER_PUBLIC_KEY);
    } else {
      throw new Error(errors_default.NO_HOLDER_PUBLIC_KEY);
    }
    const issuerDocument = await documentLoader(credential == null ? void 0 : credential.issuer);
    if ((_h = issuerDocument == null ? void 0 : issuerDocument.document) == null ? void 0 : _h.verificationMethod) {
      let verificationKey;
      const verificationMethod = (_i = issuerDocument == null ? void 0 : issuerDocument.document) == null ? void 0 : _i.verificationMethod.filter(
        (vm) => vm.type === "EcdsaSecp256k1VerificationKey2019" || vm.type === "Ed25519VerificationKey2018"
      );
      switch ((_j = verificationMethod[0]) == null ? void 0 : _j.type) {
        case "Ed25519VerificationKey2018":
          let issuerPublicKey = Buffer4.from(
            Base58.decode((_k = verificationMethod[0]) == null ? void 0 : _k.publicKeyBase58)
          ).toString("hex");
          const issuerPrivateKeyBase58 = getFullPrivateKeyBs58(
            issuerPrivateKey,
            issuerPublicKey
          );
          verificationKey = await Ed25519VerificationKey20182.from({
            controller: (_l = verificationMethod[0]) == null ? void 0 : _l.controller,
            id: (_m = verificationMethod[0]) == null ? void 0 : _m.id,
            type: (_n = verificationMethod[0]) == null ? void 0 : _n.type,
            publicKeyBase58: (_o = verificationMethod[0]) == null ? void 0 : _o.publicKeyBase58,
            privateKeyBase58: issuerPrivateKeyBase58
          });
          if (!suite)
            suite = new Ed25519Signature2018({
              key: verificationKey,
              date: issuanceDate
            });
          break;
        case "EcdsaSecp256k1VerificationKey2019":
          verificationKey = EcdsaSecp256k1VerificationKey20192.from({
            controller: (_p = verificationMethod[0]) == null ? void 0 : _p.controller,
            id: (_q = verificationMethod[0]) == null ? void 0 : _q.id,
            publicKeyHex: (_r = verificationMethod[0]) == null ? void 0 : _r.publicKeyHex,
            privateKeyHex: issuerPrivateKey
          });
          if (!suite)
            suite = new EcdsaSecp256k1Signature2019({
              key: verificationKey,
              date: issuanceDate
            });
          break;
      }
      if (!verificationKey) throw new Error(errors_default.NO_VERIFICATION_METHOD);
    } else {
      throw new Error(errors_default.NO_ISSUER_DID);
    }
    const { maskedClaims: fullMaskedClaims } = utils_default.mask.full({
      mask: {},
      credentialSubject: credential.credentialSubject,
      holderPublicKey
    });
    const maskCredential = {
      type: ["VerifiableCredential"],
      issuer: credential.issuer,
      credentialSubject: fullMaskedClaims
    };
    const maskedProof = utils_default.signature[didMethod].generate({
      data: maskCredential,
      privateKey: issuerPrivateKey
    });
    credential.credentialSubject["selectiveDisclosureMetaData"] = {
      mask: {},
      proof: maskedProof
    };
    const result = await verifiable.credential.create({
      format: ["vc"],
      credential,
      suite,
      documentLoader
    });
    return ((_s = result == null ? void 0 : result.items) == null ? void 0 : _s[0]) || null;
  } catch (error) {
    throw new Error(error || errors_default.UNKNOWN_ERROR);
  }
};
var verify = async ({
  suite = void 0,
  vc,
  documentLoader,
  issuerPublicKey,
  holderPublicKey,
  didMethod
}) => {
  var _a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k, _l, _m, _n, _o, _p;
  if (!didMethod) {
    didMethod = ((_b = (_a = getKeyValue(vc, "issuer")) == null ? void 0 : _a.split(":")) == null ? void 0 : _b[1]) || "key";
  }
  checkVcMetaData(vc);
  const issuer = getKeyValue(vc, "issuer");
  const holder = getKeyValue(vc.credentialSubject, "holder");
  if (issuer) {
    const documentLoaderResult = await documentLoader(issuer);
    if ((_c = documentLoaderResult == null ? void 0 : documentLoaderResult.document) == null ? void 0 : _c.verificationMethod) {
      const verificationMethod = (_d = documentLoaderResult == null ? void 0 : documentLoaderResult.document) == null ? void 0 : _d.verificationMethod.filter(
        (vm) => {
          var _a2;
          return vm.id === ((_a2 = vc == null ? void 0 : vc.proof) == null ? void 0 : _a2.verificationMethod);
        }
      );
      switch ((_e = verificationMethod[0]) == null ? void 0 : _e.type) {
        case "Ed25519VerificationKey2018":
          if (!issuerPublicKey)
            issuerPublicKey = Buffer4.from(
              Base58.decode((_f = verificationMethod[0]) == null ? void 0 : _f.publicKeyBase58)
            ).toString("hex");
          suite = new Ed25519Signature2018();
          break;
        case "EcdsaSecp256k1VerificationKey2019":
          if (!issuerPublicKey) issuerPublicKey = (_g = verificationMethod[0]) == null ? void 0 : _g.publicKeyHex;
          const key = EcdsaSecp256k1VerificationKey20192.from({
            controller: (_h = verificationMethod[0]) == null ? void 0 : _h.controller,
            id: (_i = verificationMethod[0]) == null ? void 0 : _i.id,
            publicKeyHex: (_j = verificationMethod[0]) == null ? void 0 : _j.publicKeyHex
          });
          suite = new EcdsaSecp256k1Signature2019({ key });
          break;
      }
      if (!verificationMethod) throw new Error(errors_default.INVALID_VC_PROOF);
    } else {
      throw new Error(errors_default.NO_ISSUER_PUBLIC_KEY);
    }
  }
  if (_3.isObject((_l = (_k = vc == null ? void 0 : vc.credentialSubject) == null ? void 0 : _k.selectiveDisclosureMetaData) == null ? void 0 : _l.mask)) {
    if (Object.keys((_n = (_m = vc == null ? void 0 : vc.credentialSubject) == null ? void 0 : _m.selectiveDisclosureMetaData) == null ? void 0 : _n.mask).length > 0 && ((_p = (_o = vc == null ? void 0 : vc.credentialSubject) == null ? void 0 : _o.selectiveDisclosureMetaData) == null ? void 0 : _p.proof)) {
      try {
        return await maskVerification({
          vc,
          holder,
          issuer,
          holderPublicKey,
          issuerPublicKey,
          didMethod,
          documentLoader
        });
      } catch (error) {
        throw Error(error);
      }
    }
  }
  try {
    return await verifiable.credential.verify({
      credential: vc,
      format: ["vc"],
      documentLoader,
      suite
    });
  } catch (error) {
    try {
      return await maskVerification({
        vc,
        holder,
        issuer,
        holderPublicKey,
        issuerPublicKey,
        didMethod,
        documentLoader
      });
    } catch (error2) {
      throw Error(errors_default.INVALID_VC_PROOF);
    }
  }
};
var maskVerification = async ({
  vc,
  holder,
  issuer,
  holderPublicKey,
  issuerPublicKey,
  didMethod,
  documentLoader
}) => {
  var _a, _b, _c, _d, _e, _f, _g, _h, _i;
  if (!holderPublicKey && holder) {
    const documentLoaderResult = await documentLoader(holder);
    if ((_a = documentLoaderResult == null ? void 0 : documentLoaderResult.document) == null ? void 0 : _a.verificationMethod) {
      const verificationMethod = (_b = documentLoaderResult == null ? void 0 : documentLoaderResult.document) == null ? void 0 : _b.verificationMethod.filter(
        (vm) => vm.type === "EcdsaSecp256k1VerificationKey2019" || vm.type === "Ed25519VerificationKey2018"
      );
      switch ((_c = verificationMethod[0]) == null ? void 0 : _c.type) {
        case "Ed25519VerificationKey2018":
          holderPublicKey = Buffer4.from(
            Base58.decode((_d = verificationMethod[0]) == null ? void 0 : _d.publicKeyBase58)
          ).toString("hex");
          break;
        case "EcdsaSecp256k1VerificationKey2019":
          holderPublicKey = (_e = verificationMethod[0]) == null ? void 0 : _e.publicKeyHex;
          break;
      }
      if (!verificationMethod) throw new Error(errors_default.INVALID_VC_PROOF);
    } else {
      throw new Error(errors_default.NO_HOLDER_PUBLIC_KEY);
    }
  }
  if (!issuerPublicKey) throw new Error(errors_default.NO_ISSUER_PUBLIC_KEY);
  if (!holderPublicKey) throw new Error(errors_default.NO_HOLDER_PUBLIC_KEY);
  const credentialSubject = __spreadValues({}, vc.credentialSubject);
  delete credentialSubject.selectiveDisclosureMetaData;
  const mask = ((_g = (_f = vc == null ? void 0 : vc.credentialSubject) == null ? void 0 : _f.selectiveDisclosureMetaData) == null ? void 0 : _g.mask) || {};
  const { maskedClaims: fullMaskedClaims } = utils_default.mask.full({
    mask,
    credentialSubject,
    holderPublicKey
  });
  const maskCredential = {
    type: ["VerifiableCredential"],
    issuer,
    credentialSubject: fullMaskedClaims
  };
  try {
    const verified = utils_default.signature[didMethod].verify({
      data: maskCredential,
      signature: (_i = (_h = vc == null ? void 0 : vc.credentialSubject) == null ? void 0 : _h.selectiveDisclosureMetaData) == null ? void 0 : _i.proof,
      publicKey: issuerPublicKey
    });
    return { verified };
  } catch (error) {
    throw Error(error || errors_default.INVALID_VC_SELECTIVE_DISCLOSURE_PROOF);
  }
};
var credential_default = { create, verify };

// src/verifiable/presentation.ts
import { EcdsaSecp256k1Signature2019 as EcdsaSecp256k1Signature20192 } from "@bloomprotocol/ecdsa-secp256k1-signature-2019";
import { Ed25519Signature2018 as Ed25519Signature20182 } from "@transmute/ed25519-signature-2018";
import { verifiable as verifiable2 } from "@transmute/vc.js";
import { EcdsaSecp256k1VerificationKey2019 as EcdsaSecp256k1VerificationKey20193 } from "@bloomprotocol/ecdsa-secp256k1-verification-key-2019";
var create2 = async ({
  suite,
  challenge = "fcc8b78e-ecca-426a-a69f-8e7c927b845f",
  issuanceDate = (/* @__PURE__ */ new Date()).toISOString(),
  domain,
  documentLoader,
  holderPrivateKey,
  verifiableCredential = [],
  masks = [],
  didMethod
}) => {
  var _a, _b, _c;
  if (!didMethod) {
    didMethod = ((_b = (_a = getKeyValue(verifiableCredential, "holder")) == null ? void 0 : _a.split(":")) == null ? void 0 : _b[1]) || "key";
  }
  const holderDoc = await privateKeyToDoc(holderPrivateKey, didMethod);
  const maskedCredentials = await Promise.all(
    verifiableCredential.map(
      (vc, index) => new Promise((resolve) => {
        const mask = masks[index];
        const credentialSubject = __spreadValues({}, vc.credentialSubject);
        delete credentialSubject.selectiveDisclosureMetaData;
        const { maskedClaims, maskedMasks } = utils_default.mask.create({
          mask,
          credentialSubject,
          holderPublicKey: holderDoc == null ? void 0 : holderDoc.publicKey
        });
        vc.credentialSubject = __spreadValues(__spreadValues({}, vc.credentialSubject), maskedClaims);
        if (!vc.credentialSubject["selectiveDisclosureMetaData"])
          vc.credentialSubject["selectiveDisclosureMetaData"] = {};
        vc.credentialSubject["selectiveDisclosureMetaData"]["mask"] = maskedMasks;
        return resolve(vc);
      })
    )
  );
  if (!suite) {
    const keyPairIssuer = await getVerificationKey({
      seed: holderPrivateKey,
      didMethod
    });
    if (didMethod === "key") {
      suite = new Ed25519Signature20182({
        key: keyPairIssuer,
        date: issuanceDate
      });
    } else if (didMethod === "ethr" || didMethod === "moon") {
      suite = new EcdsaSecp256k1Signature20192({
        key: keyPairIssuer,
        date: issuanceDate
      });
    }
  }
  const presentation = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    type: ["VerifiablePresentation"],
    verifiableCredential: maskedCredentials,
    holder: holderDoc == null ? void 0 : holderDoc.DID
  };
  const result = await verifiable2.presentation.create({
    presentation,
    format: ["vp"],
    documentLoader,
    challenge,
    domain,
    suite
  });
  return ((_c = result == null ? void 0 : result.items) == null ? void 0 : _c[0]) || null;
};
var verify2 = async ({
  suite = void 0,
  challenge = "fcc8b78e-ecca-426a-a69f-8e7c927b845f",
  domain,
  vp,
  documentLoader,
  issuerPublicKey,
  holderPublicKey,
  didMethod
}) => {
  var _a, _b, _c, _d, _e, _f, _g;
  if (!didMethod) {
    didMethod = ((_b = (_a = getKeyValue(vp, "holder")) == null ? void 0 : _a.split(":")) == null ? void 0 : _b[1]) || "key";
  }
  checkVpMetaData(vp);
  const { verifiableCredential } = vp;
  const hasMaskedProof = verifiableCredential.filter((vc) => {
    var _a2, _b2, _c2, _d2;
    return Object.keys((_b2 = (_a2 = vc == null ? void 0 : vc.credentialSubject) == null ? void 0 : _a2.selectiveDisclosureMetaData) == null ? void 0 : _b2.mask).length > 0 && ((_d2 = (_c2 = vc == null ? void 0 : vc.credentialSubject) == null ? void 0 : _c2.selectiveDisclosureMetaData) == null ? void 0 : _d2.proof);
  }).length > 0;
  if (hasMaskedProof) {
    for (const vc of verifiableCredential) {
      try {
        const result2 = await credential_default.verify({
          vc,
          documentLoader,
          holderPublicKey,
          issuerPublicKey,
          suite,
          didMethod
        });
        if (!(result2 == null ? void 0 : result2.verified)) throw Error(errors_default.INVALID_VC_PROOF);
      } catch (e) {
        throw Error(`At least one credential is not valid
${e.message}`);
      }
    }
    return { verified: true };
  }
  if (didMethod === "key") {
    suite = new Ed25519Signature20182();
  } else if (didMethod === "ethr" || didMethod === "moon") {
    const holderDocument = await documentLoader(vp.holder);
    const verificationMethod = (_c = holderDocument == null ? void 0 : holderDocument.document) == null ? void 0 : _c.verificationMethod.filter((vm) => {
      return vm.type === "EcdsaSecp256k1VerificationKey2019";
    });
    if (!holderPublicKey) holderPublicKey = (_d = verificationMethod[0]) == null ? void 0 : _d.publicKeyHex;
    const key = EcdsaSecp256k1VerificationKey20193.from({
      controller: (_e = verificationMethod[0]) == null ? void 0 : _e.controller,
      id: (_f = verificationMethod[0]) == null ? void 0 : _f.id,
      publicKeyHex: (_g = verificationMethod[0]) == null ? void 0 : _g.publicKeyHex
    });
    suite = new EcdsaSecp256k1Signature20192({ key });
  }
  const result = await verifiable2.presentation.verify({
    presentation: vp,
    format: ["vp"],
    documentLoader,
    suite,
    challenge,
    domain
  });
  return result == null ? void 0 : result.presentation;
};
var presentation_default = { create: create2, verify: verify2 };

// src/verifiable/index.ts
var verifiable_default = {
  credential: credential_default,
  presentation: presentation_default
};

// src/index.ts
var VCSD = {
  verifiable: verifiable_default,
  utils: utils_default,
  functions: functions_exports
};
var index_default = VCSD;
export {
  index_default as default,
  functions_exports as functions,
  utils_default as utils,
  verifiable_default as verifiable
};
