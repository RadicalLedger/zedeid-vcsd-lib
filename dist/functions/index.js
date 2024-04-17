'use strict';
var __createBinding =
    (this && this.__createBinding) ||
    (Object.create
        ? function (o, m, k, k2) {
              if (k2 === undefined) k2 = k;
              var desc = Object.getOwnPropertyDescriptor(m, k);
              if (!desc || ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)) {
                  desc = {
                      enumerable: true,
                      get: function () {
                          return m[k];
                      }
                  };
              }
              Object.defineProperty(o, k2, desc);
          }
        : function (o, m, k, k2) {
              if (k2 === undefined) k2 = k;
              o[k2] = m[k];
          });
var __setModuleDefault =
    (this && this.__setModuleDefault) ||
    (Object.create
        ? function (o, v) {
              Object.defineProperty(o, 'default', { enumerable: true, value: v });
          }
        : function (o, v) {
              o['default'] = v;
          });
var __importStar =
    (this && this.__importStar) ||
    function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null)
            for (var k in mod)
                if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
                    __createBinding(result, mod, k);
        __setModuleDefault(result, mod);
        return result;
    };
var __importDefault =
    (this && this.__importDefault) ||
    function (mod) {
        return mod && mod.__esModule ? mod : { default: mod };
    };
Object.defineProperty(exports, '__esModule', { value: true });
const hashUtils = __importStar(require('hash.js'));
const errors_1 = __importDefault(require('../errors'));
const ed25519_signature_2018_1 = require('@transmute/ed25519-signature-2018');
const secp256k1 = __importStar(require('secp256k1'));
const base_58_1 = __importDefault(require('base-58'));
const buffer_1 = require('buffer');
const lodash_1 = __importDefault(require('lodash'));
const edca_secp256k1_verification_2019_1 = require('edca-secp256k1-verification-2019');
function base64UrlEncode(unencoded) {
    return buffer_1.Buffer.from(unencoded)
        .toString('base64')
        .replace('+', '-')
        .replace('/', '_')
        .replace(/=+$/, '');
}
function base64UrlDecode(encoded) {
    encoded = encoded.replace('-', '+').replace('_', '/');
    while (encoded.length % 4) {
        encoded += '=';
    }
    return buffer_1.Buffer.from(encoded, 'base64').toString('utf8');
}
function blind(data, key) {
    const sha256 = hashUtils.sha256();
    const blinded = sha256.update(data + key).digest('hex');
    return blinded;
}
const sortObject = (object) => {
    if (typeof object === 'object' && object instanceof Array) {
        object.sort(function (key1, key2) {
            if (key1 < key2) return -1;
            if (key1 > key2) return 1;
            return 0;
        });
        return object;
    }
    const sortedObj = {},
        keys = Object.keys(object);
    keys.sort(function (key1, key2) {
        if (key1 < key2) return -1;
        if (key1 > key2) return 1;
        return 0;
    });
    for (const index in keys) {
        const key = keys[index];
        if (typeof object[key] == 'object') {
            sortedObj[key] = sortObject(object[key]);
        } else {
            sortedObj[key] = object[key];
        }
    }
    return sortedObj;
};
const privateKeyToDoc = async (privateKey, type = 'key') => {
    const privateKeyBuffer = new Uint8Array(buffer_1.Buffer.from(privateKey, 'hex'));
    if (type == 'ethr') {
        const publicKeyBuffer = secp256k1.publicKeyCreate(privateKeyBuffer, true);
        const publicKey = buffer_1.Buffer.from(publicKeyBuffer).toString('hex');
        const did = `did:ethr:0x${publicKey}`;
        return {
            privateKey,
            publicKey,
            DID: did
        };
    } else {
        const verificationKey = await getKeyVerificationKey({ seed: privateKey });
        const publicKey = buffer_1.Buffer.from(
            base_58_1.default.decode(verificationKey.publicKeyBase58)
        ).toString('hex');
        const did = verificationKey.id.split('#')[0];
        return {
            privateKey,
            publicKey: publicKey,
            DID: did
        };
    }
};
async function getKeyVerificationKey({ seed, includePrivateKey = false, returnKey = false }) {
    const key = await ed25519_signature_2018_1.Ed25519VerificationKey2018.generate({
        secureRandom: () => {
            return buffer_1.Buffer.from(seed, 'hex');
        }
    });
    if (returnKey) return key;
    let jwk = await key.export({
        privateKey: includePrivateKey,
        type: 'Ed25519VerificationKey2018'
    });
    return jwk;
}
async function getEthrVerificationKey({ seed, includePrivateKey = false, returnKey = false }) {
    // const didDoc = await privateKeyToDoc(seed, 'ethr');
    const key = await edca_secp256k1_verification_2019_1.EcdsaSecp256k1VerificationKey2019.generate(
        {
            seed: new Uint8Array(buffer_1.Buffer.from(seed, 'hex'))
        }
    );
    if (returnKey) return key;
    let jwk = await key.export({
        privateKey: includePrivateKey,
        publicKey: true
    });
    return jwk;
    /* const privateKeyBase58: string = base58.encode(Buffer.from(seed, 'hex'));
    const publicKeyBase58: string = base58.encode(Buffer.from(didDoc.publicKey, 'hex'));
    // TODO: create a class EcdsaSecp256k1VerificationKey2019 with signer, verifier and other attributes
    return {
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: `${didDoc.DID}#owner`,
        id: didDoc.DID,
        privateKeyBase58,
        publicKeyBase58
    }; */
}
const checkVcMetaData = (vc) => {
    var _a;
    const { issuer, type, credentialSubject, proof } = vc;
    if (!proof) {
        if (
            !((_a =
                credentialSubject === null || credentialSubject === void 0
                    ? void 0
                    : credentialSubject.selectiveDisclosureMetaData) === null || _a === void 0
                ? void 0
                : _a.proof)
        )
            throw new Error(errors_1.default.NO_PROOF_VC);
    }
    if (!issuer) {
        throw new Error(errors_1.default.NO_ISSUER);
    }
    if (!type.includes('VerifiableCredential')) {
        throw new Error(errors_1.default.TYPE_NOT_VALID);
    }
    if (!credentialSubject) {
        throw new Error(errors_1.default.NO_CLAIMS);
    }
};
const checkVpMetaData = (vp) => {
    const { holder, verifiableCredential, type, proof } = vp;
    if (!proof) {
        throw new Error(errors_1.default.NO_PROOF_VC);
    }
    if (!type.includes('VerifiablePresentation')) {
        throw new Error(errors_1.default.TYPE_NOT_VALID);
    }
    if (!holder) {
        throw new Error(errors_1.default.NO_SUBJECT_DID);
    }
    if (!verifiableCredential) {
        throw new Error(errors_1.default.NO_CREDENTIALS);
    } else if (verifiableCredential.length < 1) {
        throw new Error(errors_1.default.NO_CREDENTIALS);
    }
};
const getKeyValue = (obj, key) => {
    if (!obj) return null;
    for (const k in obj) {
        if (k === key) return obj[k];
        if (lodash_1.default.isObject(obj[k]) && !lodash_1.default.isArray(obj[k])) {
            let v = getKeyValue(obj[k], key);
            if (v) return v;
        }
    }
    return null;
};
exports.default = {
    base64UrlEncode,
    base64UrlDecode,
    blind,
    sortObject,
    privateKeyToDoc,
    checkVcMetaData,
    checkVpMetaData,
    getKeyVerificationKey,
    getEthrVerificationKey,
    getKeyValue
};
//# sourceMappingURL=index.js.map
