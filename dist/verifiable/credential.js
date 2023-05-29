"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const vc_js_1 = require("@transmute/vc.js");
const base_58_1 = __importDefault(require("base-58"));
const utils_1 = __importDefault(require("../utils"));
const functions_1 = __importDefault(require("../functions"));
const errors_1 = __importDefault(require("../errors"));
const ed25519_signature_2018_1 = require("@transmute/ed25519-signature-2018");
const buffer_1 = require("buffer");
/**
 * Generates a signed credential for given credential using a private key.
 *
 * @param {string} issuerPrivateKey - issuer's Ethereum private key in hex.
 * @param {string} issuanceDate - issuance date in ISO format YYYY-MM-DDTHH:mm:ss
 * @param {string} holderPublicKey - holders's Ethereum public key in hex.
 * @param {DocumentLoader} documentLoader - load the document for the given DID.
 * @param {Suite} suite - crypto suit used to create the verifiable credential.
 * @param {Credential} credential - credential need to be singed as key value pairs
 *
 * @return {VerifiableCredential} - signed verifiable credential of the given credential.
 */
const create = ({ issuerPrivateKey, issuanceDate = new Date().toISOString(), holderPublicKey, documentLoader, credential, suite = undefined }) => __awaiter(void 0, void 0, void 0, function* () {
    var _a, _b, _c;
    try {
        if (!holderPublicKey) {
            /* extract data from verifiable presentation */
            const { credentialSubject } = credential;
            let holder = functions_1.default.getKeyValue(credentialSubject, 'holder');
            /* vc proof checking */
            /* get holder public key using document loader */
            if (!holder)
                throw new Error(errors_1.default.NO_HOLDER_PUBLIC_KEY);
            /* load the document of the holder with holder DID */
            const documentLoaderResult = yield documentLoader(holder);
            const verificationMethod = (_b = (_a = documentLoaderResult === null || documentLoaderResult === void 0 ? void 0 : documentLoaderResult.document) === null || _a === void 0 ? void 0 : _a.verificationMethod) === null || _b === void 0 ? void 0 : _b[0];
            /* base58 to hex */
            holderPublicKey = buffer_1.Buffer.from(base_58_1.default.decode(verificationMethod === null || verificationMethod === void 0 ? void 0 : verificationMethod.publicKeyBase58)).toString('hex');
        }
        /* create a fully masked credential subject */
        const { maskedClaims: fullMaskedClaims } = utils_1.default.mask.full({
            mask: {},
            credentialSubject: credential.credentialSubject,
            holderPublicKey
        });
        /* extract data from private key */
        const issuerDoc = yield functions_1.default.privateKeyToDoc(issuerPrivateKey);
        /* create the proof with the masked credential subject and issuer private key */
        const maskCredential = {
            type: ['VerifiableCredential'],
            issuer: issuerDoc === null || issuerDoc === void 0 ? void 0 : issuerDoc.DID,
            credentialSubject: fullMaskedClaims
        };
        /* generate proof with masked credential subject */
        const maskedProof = utils_1.default.signature.generate({
            data: maskCredential,
            privateKey: issuerPrivateKey
        });
        /* add selective disclosure meta data to the credential subject */
        credential.credentialSubject['selectiveDisclosureMetaData'] = {
            mask: {},
            proof: maskedProof
        };
        /* if a suite is not given use the default */
        if (!suite) {
            const keyPairIssuer = yield functions_1.default.getVerificationKey({
                seed: issuerPrivateKey,
                returnKey: true,
                includePrivateKey: true
            });
            suite = new ed25519_signature_2018_1.Ed25519Signature2018({
                key: keyPairIssuer,
                date: issuanceDate
            });
        }
        /* create the verifiable credential */
        const result = yield vc_js_1.verifiable.credential.create({
            format: ['vc'],
            credential,
            suite,
            documentLoader
        });
        return ((_c = result === null || result === void 0 ? void 0 : result.items) === null || _c === void 0 ? void 0 : _c[0]) || null;
    }
    catch (error) {
        throw new Error(error || errors_1.default.UNKNOWN_ERROR);
    }
});
/**
 * Verify a signed verifiable credential
 *
 * @param {VerifiableCredential} vc - singed credential need to be verified.
 * @param {string} issuerPublicKey - issuer's Ethereum public key in hex.
 * @param {string} holderPublicKey - holders's Ethereum public key in hex.
 * @param {DocumentLoader} documentLoader - to load the document for the given DID.
 * @param {Suite} suite - crypto suit used to create the verifiable credential.
 *
 * @return {boolean} - result in boolean format.
 */
const verify = ({ suite = new ed25519_signature_2018_1.Ed25519Signature2018(), vc, documentLoader, issuerPublicKey, holderPublicKey }) => __awaiter(void 0, void 0, void 0, function* () {
    var _d, _e, _f, _g, _h, _j, _k, _l, _m, _o;
    /* check essential data is present in vc */
    functions_1.default.checkVcMetaData(vc);
    /* do a mask proof if available */
    if ((_e = (_d = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _d === void 0 ? void 0 : _d.selectiveDisclosureMetaData) === null || _e === void 0 ? void 0 : _e.proof) {
        /* extract data from verifiable credential */
        let issuer = functions_1.default.getKeyValue(vc, 'issuer');
        let holder = functions_1.default.getKeyValue(vc.credentialSubject, 'holder');
        /* get issuer public key using document loader */
        if (!issuerPublicKey && issuer) {
            /* load the document of the issuer with issuer DID */
            const documentLoaderResult = yield documentLoader(issuer);
            const verificationMethod = (_g = (_f = documentLoaderResult === null || documentLoaderResult === void 0 ? void 0 : documentLoaderResult.document) === null || _f === void 0 ? void 0 : _f.verificationMethod) === null || _g === void 0 ? void 0 : _g[0];
            /* base58 to hex */
            issuerPublicKey = buffer_1.Buffer.from(base_58_1.default.decode(verificationMethod === null || verificationMethod === void 0 ? void 0 : verificationMethod.publicKeyBase58)).toString('hex');
        }
        if (!holderPublicKey && holder) {
            /* load the document of the issuer with issuer DID */
            const documentLoaderResult = yield documentLoader(holder);
            const verificationMethod = (_j = (_h = documentLoaderResult === null || documentLoaderResult === void 0 ? void 0 : documentLoaderResult.document) === null || _h === void 0 ? void 0 : _h.verificationMethod) === null || _j === void 0 ? void 0 : _j[0];
            /* base58 to hex */
            holderPublicKey = buffer_1.Buffer.from(base_58_1.default.decode(verificationMethod === null || verificationMethod === void 0 ? void 0 : verificationMethod.publicKeyBase58)).toString('hex');
        }
        if (!issuerPublicKey)
            throw new Error(errors_1.default.NO_ISSUER_PUBLIC_KEY);
        if (!holderPublicKey)
            throw new Error(errors_1.default.NO_HOLDER_PUBLIC_KEY);
        /* remove selectiveDisclosureMetaData */
        let credentialSubject = Object.assign({}, vc.credentialSubject);
        delete credentialSubject.selectiveDisclosureMetaData;
        const mask = ((_l = (_k = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _k === void 0 ? void 0 : _k.selectiveDisclosureMetaData) === null || _l === void 0 ? void 0 : _l.mask) || {};
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
            const verified = utils_1.default.signature.verify({
                data: maskCredential,
                signature: (_o = (_m = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _m === void 0 ? void 0 : _m.selectiveDisclosureMetaData) === null || _o === void 0 ? void 0 : _o.proof,
                publicKey: issuerPublicKey
            });
            return { verified };
        }
        catch (error) {
            throw Error(error || errors_1.default.INVALID_VC_PROOF);
        }
    }
    /* default credential verification */
    try {
        return yield vc_js_1.verifiable.credential.verify({
            credential: vc,
            format: ['vc'],
            documentLoader,
            suite
        });
    }
    catch (error) {
        throw new Error(error || errors_1.default.INVALID_VC_PROOF);
    }
});
exports.default = { create, verify };
