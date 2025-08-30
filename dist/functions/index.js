"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getFullPrivateKeyBs58 = exports.getKeyValue = exports.checkVpMetaData = exports.checkVcMetaData = exports.privateKeyToDoc = exports.sortObject = void 0;
exports.base64UrlEncode = base64UrlEncode;
exports.base64UrlDecode = base64UrlDecode;
exports.blind = blind;
exports.getVerificationKey = getVerificationKey;
const hashUtils = __importStar(require("hash.js"));
const errors_1 = __importDefault(require("../errors"));
const ed25519_signature_2018_1 = require("@transmute/ed25519-signature-2018");
const secp256k1 = __importStar(require("secp256k1"));
const base58 = __importStar(require("base-58"));
const buffer_1 = require("buffer");
const lodash_1 = __importDefault(require("lodash"));
const ecdsa_secp256k1_verification_key_2019_1 = require("@bloomprotocol/ecdsa-secp256k1-verification-key-2019");
const keccak256_1 = __importDefault(require("keccak256"));
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
            if (key1 < key2)
                return -1;
            if (key1 > key2)
                return 1;
            return 0;
        });
        return object;
    }
    const sortedObj = {}, keys = Object.keys(object);
    keys.sort(function (key1, key2) {
        if (key1 < key2)
            return -1;
        if (key1 > key2)
            return 1;
        return 0;
    });
    for (const index in keys) {
        const key = keys[index];
        if (typeof object[key] == 'object') {
            sortedObj[key] = sortObject(object[key]);
        }
        else {
            sortedObj[key] = object[key];
        }
    }
    return sortedObj;
};
exports.sortObject = sortObject;
const privateKeyToDoc = async (privateKey, didMethod = 'key') => {
    let publicKey, did;
    const privateKeyBuffer = new Uint8Array(buffer_1.Buffer.from(privateKey, 'hex'));
    if (didMethod == 'ethr') {
        const publicKeyBuffer = secp256k1.publicKeyCreate(privateKeyBuffer, false);
        const publicKeyBufferCompressed = secp256k1.publicKeyCreate(privateKeyBuffer, true);
        publicKey = buffer_1.Buffer.from(publicKeyBufferCompressed).toString('hex');
        const addressBuffer = buffer_1.Buffer.from((0, keccak256_1.default)(buffer_1.Buffer.from(publicKeyBuffer.slice(1)))).slice(-20);
        did = `did:ethr:0x${addressBuffer.toString('hex')}`;
    }
    else {
        const verificationKey = await getVerificationKey({
            seed: privateKey,
            didMethod
        });
        const verificationKeyExport = await verificationKey.export({
            type: 'Ed25519VerificationKey2018'
        });
        publicKey = buffer_1.Buffer.from(base58.decode(verificationKeyExport.publicKeyBase58)).toString('hex');
        did = verificationKey.id.split('#')[0];
    }
    return {
        privateKey,
        publicKey,
        DID: did
    };
};
exports.privateKeyToDoc = privateKeyToDoc;
async function getVerificationKey({ seed, didMethod }) {
    let key = null;
    if (didMethod === 'key') {
        key = await ed25519_signature_2018_1.Ed25519VerificationKey2018.generate({
            secureRandom: () => {
                return buffer_1.Buffer.from(seed, 'hex');
            }
        });
    }
    else if (didMethod === 'ethr' || didMethod === 'moon') {
        const document = await privateKeyToDoc(seed, didMethod);
        key = await ecdsa_secp256k1_verification_key_2019_1.EcdsaSecp256k1VerificationKey2019.generate({
            seed: new Uint8Array(buffer_1.Buffer.from(seed, 'hex')),
            controller: document.DID,
            id: `${document.DID}#owner`
        });
    }
    return key;
}
const checkVcMetaData = (vc) => {
    var _a;
    const { issuer, type, credentialSubject, proof } = vc;
    if (!proof) {
        if (!((_a = credentialSubject === null || credentialSubject === void 0 ? void 0 : credentialSubject.selectiveDisclosureMetaData) === null || _a === void 0 ? void 0 : _a.proof))
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
exports.checkVcMetaData = checkVcMetaData;
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
    }
    else if (verifiableCredential.length < 1) {
        throw new Error(errors_1.default.NO_CREDENTIALS);
    }
};
exports.checkVpMetaData = checkVpMetaData;
const getKeyValue = (obj, key) => {
    if (!obj)
        return null;
    for (const k in obj) {
        if (k === key)
            return obj[k];
        if (lodash_1.default.isObject(obj[k]) && !lodash_1.default.isArray(obj[k])) {
            let v = getKeyValue(obj[k], key);
            if (v)
                return v;
        }
    }
    return null;
};
exports.getKeyValue = getKeyValue;
const getFullPrivateKeyBs58 = (privateKey, publicKey) => {
    const seed = buffer_1.Buffer.from(privateKey, 'hex');
    const fullIssuerPrivateKey = buffer_1.Buffer.concat([seed, buffer_1.Buffer.from(publicKey, 'hex')]);
    const privateKeyBase58 = base58.encode(fullIssuerPrivateKey);
    return privateKeyBase58;
};
exports.getFullPrivateKeyBs58 = getFullPrivateKeyBs58;
//# sourceMappingURL=index.js.map