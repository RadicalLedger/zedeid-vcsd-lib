"use strict";
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
const ecdsa_secp256k1_signature_2019_1 = require("@bloomprotocol/ecdsa-secp256k1-signature-2019");
const edca_secp256k1_verification_2019_1 = require("edca-secp256k1-verification-2019");
const buffer_1 = require("buffer");
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
            didMethod = ((_b = (_a = functions_1.default.getKeyValue(credential, 'issuer')) === null || _a === void 0 ? void 0 : _a.split(':')) === null || _b === void 0 ? void 0 : _b[1]) || 'key';
        }
        /* extract data from verifiable credential */
        const { credentialSubject } = credential;
        let holder = functions_1.default.getKeyValue(credentialSubject, 'holder');
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
                    holderPublicKey = buffer_1.Buffer.from(base_58_1.default.decode((_f = verificationMethod[0]) === null || _f === void 0 ? void 0 : _f.publicKeyBase58)).toString('hex');
                    break;
                case 'EcdsaSecp256k1VerificationKey2019':
                    holderPublicKey = (_g = verificationMethod[0]) === null || _g === void 0 ? void 0 : _g.publicKeyHex;
                    break;
            }
            if (!holderPublicKey)
                throw new Error(errors_1.default.NO_HOLDER_PUBLIC_KEY);
        }
        else if (holder === null || holder === void 0 ? void 0 : holder.startsWith('did:ethr')) {
            holderPublicKey = holder === null || holder === void 0 ? void 0 : holder.replace('did:ethr:0x', '');
        }
        /* get issuer verification key using document loader */
        const issuerDocument = await documentLoader(credential === null || credential === void 0 ? void 0 : credential.issuer);
        let verificationKey;
        let verificationMethod;
        if ((_h = issuerDocument === null || issuerDocument === void 0 ? void 0 : issuerDocument.document) === null || _h === void 0 ? void 0 : _h.verificationMethod) {
            verificationMethod = (_j = issuerDocument === null || issuerDocument === void 0 ? void 0 : issuerDocument.document) === null || _j === void 0 ? void 0 : _j.verificationMethod.filter((vm) => vm.type === 'EcdsaSecp256k1VerificationKey2019' ||
                vm.type === 'Ed25519VerificationKey2018');
            switch ((_k = verificationMethod[0]) === null || _k === void 0 ? void 0 : _k.type) {
                case 'Ed25519VerificationKey2018':
                    verificationKey = await ed25519_signature_2018_1.Ed25519VerificationKey2018.from({
                        controller: (_l = verificationMethod[0]) === null || _l === void 0 ? void 0 : _l.controller,
                        id: (_m = verificationMethod[0]) === null || _m === void 0 ? void 0 : _m.id,
                        type: (_o = verificationMethod[0]) === null || _o === void 0 ? void 0 : _o.type,
                        publicKeyBase58: (_p = verificationMethod[0]) === null || _p === void 0 ? void 0 : _p.publicKeyBase58,
                        privateKeyBase58: base_58_1.default.encode(buffer_1.Buffer.from(issuerPrivateKey, 'hex'))
                    });
                    break;
                case 'EcdsaSecp256k1VerificationKey2019':
                    verificationKey = edca_secp256k1_verification_2019_1.EcdsaSecp256k1VerificationKey2019.from({
                        controller: (_q = verificationMethod[0]) === null || _q === void 0 ? void 0 : _q.controller,
                        id: (_r = verificationMethod[0]) === null || _r === void 0 ? void 0 : _r.id,
                        publicKeyHex: (_s = verificationMethod[0]) === null || _s === void 0 ? void 0 : _s.publicKeyHex,
                        privateKeyHex: issuerPrivateKey
                    });
                    break;
            }
            if (!verificationKey)
                throw new Error(errors_1.default.NO_VERIFICATION_METHOD);
        }
        else if (didMethod == 'ethr') {
            verificationKey = await edca_secp256k1_verification_2019_1.EcdsaSecp256k1VerificationKey2019.from({
                controller: credential === null || credential === void 0 ? void 0 : credential.issuer,
                id: credential === null || credential === void 0 ? void 0 : credential.issuer,
                privateKeyHex: issuerPrivateKey,
                publicKeyHex: credential === null || credential === void 0 ? void 0 : credential.issuer.split('did:ethr:0x')[1]
            });
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
        /* if a suite is not given use the default */
        if (!suite) {
            if (!verificationMethod) {
                suite = new ed25519_signature_2018_1.Ed25519Signature2018({ key: verificationKey, date: issuanceDate });
            }
            else {
                switch ((_t = verificationMethod[0]) === null || _t === void 0 ? void 0 : _t.type) {
                    case 'Ed25519VerificationKey2018':
                        suite = new ed25519_signature_2018_1.Ed25519Signature2018({
                            key: verificationKey,
                            date: issuanceDate
                        });
                        break;
                    case 'EcdsaSecp256k1VerificationKey2019':
                        suite = new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019({
                            key: verificationKey,
                            date: issuanceDate
                        });
                        break;
                }
            }
        }
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
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t;
    /* extract the did type */
    if (!didMethod) {
        didMethod = ((_b = (_a = functions_1.default.getKeyValue(vc, 'issuer')) === null || _a === void 0 ? void 0 : _a.split(':')) === null || _b === void 0 ? void 0 : _b[1]) || 'key';
    }
    /* check essential data is present in vc */
    functions_1.default.checkVcMetaData(vc);
    /* do a mask proof if available */
    if ((_d = (_c = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _c === void 0 ? void 0 : _c.selectiveDisclosureMetaData) === null || _d === void 0 ? void 0 : _d.proof) {
        /* extract data from verifiable credential */
        let issuer = functions_1.default.getKeyValue(vc, 'issuer');
        let holder = functions_1.default.getKeyValue(vc.credentialSubject, 'holder');
        /* get issuer public key using document loader */
        if (!issuerPublicKey && issuer) {
            /* load the document of the issuer with issuer DID */
            const documentLoaderResult = await documentLoader(issuer);
            if ((_e = documentLoaderResult === null || documentLoaderResult === void 0 ? void 0 : documentLoaderResult.document) === null || _e === void 0 ? void 0 : _e.verificationMethod) {
                const verificationMethod = (_f = documentLoaderResult === null || documentLoaderResult === void 0 ? void 0 : documentLoaderResult.document) === null || _f === void 0 ? void 0 : _f.verificationMethod.filter((vm) => { var _a; return vm.id === ((_a = vc === null || vc === void 0 ? void 0 : vc.proof) === null || _a === void 0 ? void 0 : _a.verificationMethod); });
                switch ((_g = verificationMethod[0]) === null || _g === void 0 ? void 0 : _g.type) {
                    case 'Ed25519VerificationKey2018':
                        issuerPublicKey = buffer_1.Buffer.from(base_58_1.default.decode((_h = verificationMethod[0]) === null || _h === void 0 ? void 0 : _h.publicKeyBase58)).toString('hex');
                        suite = new ed25519_signature_2018_1.Ed25519Signature2018();
                        break;
                    case 'EcdsaSecp256k1VerificationKey2019':
                        issuerPublicKey = (_j = verificationMethod[0]) === null || _j === void 0 ? void 0 : _j.publicKeyHex;
                        suite = new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019();
                        break;
                }
                if (!verificationMethod)
                    throw new Error(errors_1.default.INVALID_VC_PROOF);
            }
            else if (issuer === null || issuer === void 0 ? void 0 : issuer.startsWith('did:ethr')) {
                issuerPublicKey = issuer === null || issuer === void 0 ? void 0 : issuer.replace('did:ethr:0x', '');
            }
        }
        if (!holderPublicKey && holder) {
            /* load the document of the holder with holder DID */
            const documentLoaderResult = await documentLoader(holder);
            if ((_k = documentLoaderResult === null || documentLoaderResult === void 0 ? void 0 : documentLoaderResult.document) === null || _k === void 0 ? void 0 : _k.verificationMethod) {
                const verificationMethod = (_l = documentLoaderResult === null || documentLoaderResult === void 0 ? void 0 : documentLoaderResult.document) === null || _l === void 0 ? void 0 : _l.verificationMethod.filter((vm) => vm.type === 'EcdsaSecp256k1VerificationKey2019' ||
                    vm.type === 'Ed25519VerificationKey2018');
                switch ((_m = verificationMethod[0]) === null || _m === void 0 ? void 0 : _m.type) {
                    case 'Ed25519VerificationKey2018':
                        holderPublicKey = buffer_1.Buffer.from(base_58_1.default.decode((_o = verificationMethod[0]) === null || _o === void 0 ? void 0 : _o.publicKeyBase58)).toString('hex');
                        break;
                    case 'EcdsaSecp256k1VerificationKey2019':
                        holderPublicKey = (_p = verificationMethod[0]) === null || _p === void 0 ? void 0 : _p.publicKeyHex;
                        break;
                }
                if (!verificationMethod)
                    throw new Error(errors_1.default.INVALID_VC_PROOF);
            }
            else if (holder === null || holder === void 0 ? void 0 : holder.startsWith('did:ethr')) {
                holderPublicKey = holder === null || holder === void 0 ? void 0 : holder.replace('did:ethr:0x', '');
            }
        }
        if (!issuerPublicKey)
            throw new Error(errors_1.default.NO_ISSUER_PUBLIC_KEY);
        if (!holderPublicKey)
            throw new Error(errors_1.default.NO_HOLDER_PUBLIC_KEY);
        /* remove selectiveDisclosureMetaData */
        let credentialSubject = Object.assign({}, vc.credentialSubject);
        delete credentialSubject.selectiveDisclosureMetaData;
        const mask = ((_r = (_q = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _q === void 0 ? void 0 : _q.selectiveDisclosureMetaData) === null || _r === void 0 ? void 0 : _r.mask) || {};
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
                signature: (_t = (_s = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _s === void 0 ? void 0 : _s.selectiveDisclosureMetaData) === null || _t === void 0 ? void 0 : _t.proof,
                publicKey: issuerPublicKey
            });
            return { verified };
        }
        catch (error) {
            throw Error(error || errors_1.default.INVALID_VC_SELECTIVE_DISCLOSURE_PROOF);
        }
    }
    if (!suite) {
        if (didMethod === 'key') {
            suite = new ed25519_signature_2018_1.Ed25519Signature2018();
        }
        else if (didMethod === 'ethr') {
            suite = new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019();
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
        throw new Error(error || errors_1.default.INVALID_VC_PROOF);
    }
};
exports.default = { create, verify };
//# sourceMappingURL=credential.js.map