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
const ecdsa_secp256k1_signature_2019_1 = require("@bloomprotocol/ecdsa-secp256k1-signature-2019");
const ecdsa_secp256k1_verification_key_2019_1 = require("@bloomprotocol/ecdsa-secp256k1-verification-key-2019");
const ed25519_signature_2018_1 = require("@transmute/ed25519-signature-2018");
const vc_js_1 = require("@transmute/vc.js");
const base58 = __importStar(require("base-58"));
const buffer_1 = require("buffer");
const lodash_1 = __importDefault(require("lodash"));
const errors_1 = __importDefault(require("../errors"));
const functions_1 = require("../functions");
const utils_1 = __importDefault(require("../utils"));
/**
 * Generates a signed credential for given credential using a private key.
 *
 * @param {string} issuerPrivateKey - issuer's private key in hex.
 * @param {string} issuanceDate - issuance date in ISO format YYYY-MM-DDTHH:mm:ss
 * @param {string} holderPublicKey - holders's public key in hex.
 * @param {DocumentLoader} documentLoader - load the document for the given DID.
 * @param {Suite} suite - crypto suit used to create the verifiable credential.
 * @param {Credential} credential - credential need to be singed as key value pairs
 *
 * @return {VerifiableCredential} - signed verifiable credential of the given credential.
 */
const create = async ({ issuerPrivateKey, issuanceDate = new Date().toISOString(), documentLoader, credential, suite = undefined, didMethod }) => {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t, _u;
    try {
        /* extract the did type */
        if (!didMethod) {
            didMethod = ((_b = (_a = (0, functions_1.getKeyValue)(credential, 'issuer')) === null || _a === void 0 ? void 0 : _a.split(':')) === null || _b === void 0 ? void 0 : _b[1]) || 'key';
        }
        /* extract data from verifiable credential */
        const { credentialSubject } = credential;
        const holder = (0, functions_1.getKeyValue)(credentialSubject, 'holder');
        /* vc proof checking */
        if (!holder)
            throw new Error(errors_1.default.NO_HOLDER_PUBLIC_KEY);
        /* load the document of the holder with holder DID */
        const documentLoaderResult = await documentLoader(holder);
        let holderPublicKey;
        /* get holder public key using document loader */
        if ((_c = documentLoaderResult === null || documentLoaderResult === void 0 ? void 0 : documentLoaderResult.document) === null || _c === void 0 ? void 0 : _c.verificationMethod) {
            const verificationMethod = (_d = documentLoaderResult === null || documentLoaderResult === void 0 ? void 0 : documentLoaderResult.document) === null || _d === void 0 ? void 0 : _d.verificationMethod.filter((vm) => vm.type === 'EcdsaSecp256k1VerificationKey2019' ||
                vm.type === 'Ed25519VerificationKey2018');
            switch ((_e = verificationMethod[0]) === null || _e === void 0 ? void 0 : _e.type) {
                case 'Ed25519VerificationKey2018':
                    holderPublicKey = buffer_1.Buffer.from(base58.decode((_f = verificationMethod[0]) === null || _f === void 0 ? void 0 : _f.publicKeyBase58)).toString('hex');
                    break;
                case 'EcdsaSecp256k1VerificationKey2019':
                    holderPublicKey = (_g = verificationMethod[0]) === null || _g === void 0 ? void 0 : _g.publicKeyHex;
                    break;
            }
            if (!holderPublicKey)
                throw new Error(errors_1.default.NO_HOLDER_PUBLIC_KEY);
        }
        else {
            throw new Error(errors_1.default.NO_HOLDER_PUBLIC_KEY);
        }
        /* get issuer verification key using document loader */
        const issuerDocument = await documentLoader(credential === null || credential === void 0 ? void 0 : credential.issuer);
        if ((_h = issuerDocument === null || issuerDocument === void 0 ? void 0 : issuerDocument.document) === null || _h === void 0 ? void 0 : _h.verificationMethod) {
            let verificationKey;
            const verificationMethod = (_j = issuerDocument === null || issuerDocument === void 0 ? void 0 : issuerDocument.document) === null || _j === void 0 ? void 0 : _j.verificationMethod.filter((vm) => vm.type === 'EcdsaSecp256k1VerificationKey2019' ||
                vm.type === 'Ed25519VerificationKey2018');
            switch ((_k = verificationMethod[0]) === null || _k === void 0 ? void 0 : _k.type) {
                case 'Ed25519VerificationKey2018':
                    let issuerPublicKey = buffer_1.Buffer.from(base58.decode((_l = verificationMethod[0]) === null || _l === void 0 ? void 0 : _l.publicKeyBase58)).toString('hex');
                    const issuerPrivateKeyBase58 = (0, functions_1.getFullPrivateKeyBs58)(issuerPrivateKey, issuerPublicKey);
                    verificationKey = await ed25519_signature_2018_1.Ed25519VerificationKey2018.from({
                        controller: (_m = verificationMethod[0]) === null || _m === void 0 ? void 0 : _m.controller,
                        id: (_o = verificationMethod[0]) === null || _o === void 0 ? void 0 : _o.id,
                        type: (_p = verificationMethod[0]) === null || _p === void 0 ? void 0 : _p.type,
                        publicKeyBase58: (_q = verificationMethod[0]) === null || _q === void 0 ? void 0 : _q.publicKeyBase58,
                        privateKeyBase58: issuerPrivateKeyBase58
                    });
                    if (!suite)
                        suite = new ed25519_signature_2018_1.Ed25519Signature2018({
                            key: verificationKey,
                            date: issuanceDate
                        });
                    break;
                case 'EcdsaSecp256k1VerificationKey2019':
                    verificationKey = ecdsa_secp256k1_verification_key_2019_1.EcdsaSecp256k1VerificationKey2019.from({
                        controller: (_r = verificationMethod[0]) === null || _r === void 0 ? void 0 : _r.controller,
                        id: (_s = verificationMethod[0]) === null || _s === void 0 ? void 0 : _s.id,
                        publicKeyHex: (_t = verificationMethod[0]) === null || _t === void 0 ? void 0 : _t.publicKeyHex,
                        privateKeyHex: issuerPrivateKey
                    });
                    if (!suite)
                        suite = new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019({
                            key: verificationKey,
                            date: issuanceDate
                        });
                    break;
            }
            if (!verificationKey)
                throw new Error(errors_1.default.NO_VERIFICATION_METHOD);
        }
        else {
            throw new Error(errors_1.default.NO_ISSUER_DID);
        }
        /* create a fully masked credential subject */
        const { maskedClaims: fullMaskedClaims } = utils_1.default.mask.full({
            mask: {},
            credentialSubject: credential.credentialSubject,
            holderPublicKey
        });
        /* create the proof with the masked credential subject and issuer private key */
        const maskCredential = {
            type: ['VerifiableCredential'],
            issuer: credential.issuer,
            credentialSubject: fullMaskedClaims
        };
        /* generate proof with masked credential subject */
        const maskedProof = utils_1.default.signature[didMethod].generate({
            data: maskCredential,
            privateKey: issuerPrivateKey
        });
        /* add selective disclosure meta data to the credential subject */
        credential.credentialSubject['selectiveDisclosureMetaData'] = {
            mask: {},
            proof: maskedProof
        };
        /* create the verifiable credential */
        const result = await vc_js_1.verifiable.credential.create({
            format: ['vc'],
            credential,
            suite,
            documentLoader
        });
        return ((_u = result === null || result === void 0 ? void 0 : result.items) === null || _u === void 0 ? void 0 : _u[0]) || null;
    }
    catch (error) {
        throw new Error(error || errors_1.default.UNKNOWN_ERROR);
    }
};
/**
 * Verify a signed verifiable credential
 *
 * @param {VerifiableCredential} vc - singed credential need to be verified.
 * @param {string} issuerPublicKey - issuer's public key in hex.
 * @param {string} holderPublicKey - holders's public key in hex.
 * @param {DocumentLoader} documentLoader - to load the document for the given DID.
 * @param {Suite} suite - crypto suit used to create the verifiable credential.
 *
 * @return {boolean} - result in boolean format.
 */
const verify = async ({ suite = undefined, vc, documentLoader, issuerPublicKey, holderPublicKey, didMethod }) => {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r;
    /* extract the did type */
    if (!didMethod) {
        didMethod = ((_b = (_a = (0, functions_1.getKeyValue)(vc, 'issuer')) === null || _a === void 0 ? void 0 : _a.split(':')) === null || _b === void 0 ? void 0 : _b[1]) || 'key';
    }
    /* check essential data is present in vc */
    (0, functions_1.checkVcMetaData)(vc);
    /* extract data from verifiable credential */
    const issuer = (0, functions_1.getKeyValue)(vc, 'issuer');
    const holder = (0, functions_1.getKeyValue)(vc.credentialSubject, 'holder');
    /* get issuer public key using document loader */
    if (issuer) {
        /* load the document of the issuer with issuer DID */
        const documentLoaderResult = await documentLoader(issuer);
        if ((_c = documentLoaderResult === null || documentLoaderResult === void 0 ? void 0 : documentLoaderResult.document) === null || _c === void 0 ? void 0 : _c.verificationMethod) {
            const verificationMethod = (_d = documentLoaderResult === null || documentLoaderResult === void 0 ? void 0 : documentLoaderResult.document) === null || _d === void 0 ? void 0 : _d.verificationMethod.filter((vm) => { var _a; return vm.id === ((_a = vc === null || vc === void 0 ? void 0 : vc.proof) === null || _a === void 0 ? void 0 : _a.verificationMethod); });
            switch ((_e = verificationMethod[0]) === null || _e === void 0 ? void 0 : _e.type) {
                case 'Ed25519VerificationKey2018':
                    if (!issuerPublicKey)
                        issuerPublicKey = buffer_1.Buffer.from(base58.decode((_f = verificationMethod[0]) === null || _f === void 0 ? void 0 : _f.publicKeyBase58)).toString('hex');
                    suite = new ed25519_signature_2018_1.Ed25519Signature2018();
                    break;
                case 'EcdsaSecp256k1VerificationKey2019':
                    if (!issuerPublicKey)
                        issuerPublicKey = (_g = verificationMethod[0]) === null || _g === void 0 ? void 0 : _g.publicKeyHex;
                    const key = ecdsa_secp256k1_verification_key_2019_1.EcdsaSecp256k1VerificationKey2019.from({
                        controller: (_h = verificationMethod[0]) === null || _h === void 0 ? void 0 : _h.controller,
                        id: (_j = verificationMethod[0]) === null || _j === void 0 ? void 0 : _j.id,
                        publicKeyHex: (_k = verificationMethod[0]) === null || _k === void 0 ? void 0 : _k.publicKeyHex
                    });
                    suite = new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019({ key });
                    break;
            }
            if (!verificationMethod)
                throw new Error(errors_1.default.INVALID_VC_PROOF);
        }
        else {
            throw new Error(errors_1.default.NO_ISSUER_PUBLIC_KEY);
        }
    }
    /* do a mask proof if available */
    if (lodash_1.default.isObject((_m = (_l = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _l === void 0 ? void 0 : _l.selectiveDisclosureMetaData) === null || _m === void 0 ? void 0 : _m.mask)) {
        if (Object.keys((_p = (_o = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _o === void 0 ? void 0 : _o.selectiveDisclosureMetaData) === null || _p === void 0 ? void 0 : _p.mask).length > 0 &&
            ((_r = (_q = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _q === void 0 ? void 0 : _q.selectiveDisclosureMetaData) === null || _r === void 0 ? void 0 : _r.proof)) {
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
            }
            catch (error) {
                throw Error(error);
            }
        }
    }
    /* default credential verification */
    try {
        return await vc_js_1.verifiable.credential.verify({
            credential: vc,
            format: ['vc'],
            documentLoader,
            suite
        });
    }
    catch (error) {
        /* as a fallback verification check if the masked proof is valid */
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
        }
        catch (error) {
            throw Error(errors_1.default.INVALID_VC_PROOF);
        }
    }
};
const maskVerification = async ({ vc, holder, issuer, holderPublicKey, issuerPublicKey, didMethod, documentLoader }) => {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j;
    if (!holderPublicKey && holder) {
        /* load the document of the holder with holder DID */
        const documentLoaderResult = await documentLoader(holder);
        if ((_a = documentLoaderResult === null || documentLoaderResult === void 0 ? void 0 : documentLoaderResult.document) === null || _a === void 0 ? void 0 : _a.verificationMethod) {
            const verificationMethod = (_b = documentLoaderResult === null || documentLoaderResult === void 0 ? void 0 : documentLoaderResult.document) === null || _b === void 0 ? void 0 : _b.verificationMethod.filter((vm) => vm.type === 'EcdsaSecp256k1VerificationKey2019' ||
                vm.type === 'Ed25519VerificationKey2018');
            switch ((_c = verificationMethod[0]) === null || _c === void 0 ? void 0 : _c.type) {
                case 'Ed25519VerificationKey2018':
                    holderPublicKey = buffer_1.Buffer.from(base58.decode((_d = verificationMethod[0]) === null || _d === void 0 ? void 0 : _d.publicKeyBase58)).toString('hex');
                    break;
                case 'EcdsaSecp256k1VerificationKey2019':
                    holderPublicKey = (_e = verificationMethod[0]) === null || _e === void 0 ? void 0 : _e.publicKeyHex;
                    break;
            }
            if (!verificationMethod)
                throw new Error(errors_1.default.INVALID_VC_PROOF);
        }
        else {
            throw new Error(errors_1.default.NO_HOLDER_PUBLIC_KEY);
        }
    }
    if (!issuerPublicKey)
        throw new Error(errors_1.default.NO_ISSUER_PUBLIC_KEY);
    if (!holderPublicKey)
        throw new Error(errors_1.default.NO_HOLDER_PUBLIC_KEY);
    /* remove selectiveDisclosureMetaData */
    const credentialSubject = Object.assign({}, vc.credentialSubject);
    delete credentialSubject.selectiveDisclosureMetaData;
    const mask = ((_g = (_f = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _f === void 0 ? void 0 : _f.selectiveDisclosureMetaData) === null || _g === void 0 ? void 0 : _g.mask) || {};
    /* create a masked credential subject */
    const { maskedClaims: fullMaskedClaims } = utils_1.default.mask.full({
        mask,
        credentialSubject,
        holderPublicKey
    });
    /* create the proof with the masked credential subject and issuer private key */
    const maskCredential = {
        type: ['VerifiableCredential'],
        issuer,
        credentialSubject: fullMaskedClaims
    };
    try {
        const verified = utils_1.default.signature[didMethod].verify({
            data: maskCredential,
            signature: (_j = (_h = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _h === void 0 ? void 0 : _h.selectiveDisclosureMetaData) === null || _j === void 0 ? void 0 : _j.proof,
            publicKey: issuerPublicKey
        });
        return { verified };
    }
    catch (error) {
        throw Error(error || errors_1.default.INVALID_VC_SELECTIVE_DISCLOSURE_PROOF);
    }
};
exports.default = { create, verify };
//# sourceMappingURL=credential.js.map