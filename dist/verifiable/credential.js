'use strict';
var __importDefault =
    (this && this.__importDefault) ||
    function (mod) {
        return mod && mod.__esModule ? mod : { default: mod };
    };
Object.defineProperty(exports, '__esModule', { value: true });
const vc_js_1 = require('@transmute/vc.js');
const base_58_1 = __importDefault(require('base-58'));
const utils_1 = __importDefault(require('../utils'));
const functions_1 = __importDefault(require('../functions'));
const errors_1 = __importDefault(require('../errors'));
const ed25519_signature_2018_1 = require('@transmute/ed25519-signature-2018');
const ecdsa_secp256k1_signature_2019_1 = require('@bloomprotocol/ecdsa-secp256k1-signature-2019');
const buffer_1 = require('buffer');
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
const create = async ({
    issuerPrivateKey,
    issuanceDate = new Date().toISOString(),
    holderPublicKey,
    documentLoader,
    credential,
    suite = undefined,
    type = 'key'
}) => {
    var _a, _b, _c, _d;
    try {
        if (!holderPublicKey) {
            /* extract data from verifiable credential */
            const { credentialSubject } = credential;
            let holder = functions_1.default.getKeyValue(credentialSubject, 'holder');
            /* vc proof checking */
            /* get holder public key using document loader */
            if (!holder) throw new Error(errors_1.default.NO_HOLDER_PUBLIC_KEY);
            /* load the document of the holder with holder DID */
            const documentLoaderResult = await documentLoader(holder);
            if (
                (_a =
                    documentLoaderResult === null || documentLoaderResult === void 0
                        ? void 0
                        : documentLoaderResult.document) === null || _a === void 0
                    ? void 0
                    : _a.verificationMethod
            ) {
                const verificationMethod =
                    (_c =
                        (_b =
                            documentLoaderResult === null || documentLoaderResult === void 0
                                ? void 0
                                : documentLoaderResult.document) === null || _b === void 0
                            ? void 0
                            : _b.verificationMethod) === null || _c === void 0
                        ? void 0
                        : _c[0];
                /* base58 to hex */
                holderPublicKey = buffer_1.Buffer.from(
                    base_58_1.default.decode(
                        verificationMethod === null || verificationMethod === void 0
                            ? void 0
                            : verificationMethod.publicKeyBase58
                    )
                ).toString('hex');
            } else if (
                holder === null || holder === void 0 ? void 0 : holder.startsWith('did:ethr')
            ) {
                holderPublicKey =
                    holder === null || holder === void 0
                        ? void 0
                        : holder.replace('did:ethr:0x', '');
            }
        }
        /* create a fully masked credential subject */
        const { maskedClaims: fullMaskedClaims } = utils_1.default.mask.full({
            mask: {},
            credentialSubject: credential.credentialSubject,
            holderPublicKey
        });
        /* extract data from private key */
        const issuerDoc = await functions_1.default.privateKeyToDoc(issuerPrivateKey, type);
        /* create the proof with the masked credential subject and issuer private key */
        const maskCredential = {
            type: ['VerifiableCredential'],
            issuer: issuerDoc === null || issuerDoc === void 0 ? void 0 : issuerDoc.DID,
            credentialSubject: fullMaskedClaims
        };
        /* generate proof with masked credential subject */
        const maskedProof = utils_1.default.signature[type].generate({
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
            if (type === 'key') {
                const keyPairIssuer = await functions_1.default.getKeyVerificationKey({
                    seed: issuerPrivateKey,
                    returnKey: true
                });
                suite = new ed25519_signature_2018_1.Ed25519Signature2018({
                    key: keyPairIssuer,
                    date: issuanceDate
                });
            } else if (type === 'ethr') {
                const keyPairIssuer = await functions_1.default.getEthrVerificationKey({
                    seed: issuerPrivateKey,
                    returnKey: true
                });
                suite = new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019({
                    key: keyPairIssuer,
                    date: issuanceDate
                });
            }
        }
        /* create the verifiable credential */
        const result = await vc_js_1.verifiable.credential.create({
            format: ['vc'],
            credential,
            suite,
            documentLoader
        });
        return (
            ((_d = result === null || result === void 0 ? void 0 : result.items) === null ||
            _d === void 0
                ? void 0
                : _d[0]) || null
        );
    } catch (error) {
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
const verify = async ({
    suite = undefined,
    vc,
    documentLoader,
    issuerPublicKey,
    holderPublicKey,
    type = 'key'
}) => {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m;
    /* check essential data is present in vc */
    functions_1.default.checkVcMetaData(vc);
    /* do a mask proof if available */
    if (
        (_b =
            (_a = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null ||
            _a === void 0
                ? void 0
                : _a.selectiveDisclosureMetaData) === null || _b === void 0
            ? void 0
            : _b.proof
    ) {
        /* extract data from verifiable credential */
        let issuer = functions_1.default.getKeyValue(vc, 'issuer');
        let holder = functions_1.default.getKeyValue(vc.credentialSubject, 'holder');
        /* get issuer public key using document loader */
        if (!issuerPublicKey && issuer) {
            /* load the document of the issuer with issuer DID */
            const documentLoaderResult = await documentLoader(issuer);
            if (
                (_c =
                    documentLoaderResult === null || documentLoaderResult === void 0
                        ? void 0
                        : documentLoaderResult.document) === null || _c === void 0
                    ? void 0
                    : _c.verificationMethod
            ) {
                const verificationMethod =
                    (_e =
                        (_d =
                            documentLoaderResult === null || documentLoaderResult === void 0
                                ? void 0
                                : documentLoaderResult.document) === null || _d === void 0
                            ? void 0
                            : _d.verificationMethod) === null || _e === void 0
                        ? void 0
                        : _e[0];
                /* base58 to hex */
                issuerPublicKey = buffer_1.Buffer.from(
                    base_58_1.default.decode(
                        verificationMethod === null || verificationMethod === void 0
                            ? void 0
                            : verificationMethod.publicKeyBase58
                    )
                ).toString('hex');
            } else if (
                issuer === null || issuer === void 0 ? void 0 : issuer.startsWith('did:ethr')
            ) {
                issuerPublicKey =
                    issuer === null || issuer === void 0
                        ? void 0
                        : issuer.replace('did:ethr:0x', '');
            }
        }
        if (!holderPublicKey && holder) {
            /* load the document of the holder with holder DID */
            const documentLoaderResult = await documentLoader(holder);
            if (
                (_f =
                    documentLoaderResult === null || documentLoaderResult === void 0
                        ? void 0
                        : documentLoaderResult.document) === null || _f === void 0
                    ? void 0
                    : _f.verificationMethod
            ) {
                const verificationMethod =
                    (_h =
                        (_g =
                            documentLoaderResult === null || documentLoaderResult === void 0
                                ? void 0
                                : documentLoaderResult.document) === null || _g === void 0
                            ? void 0
                            : _g.verificationMethod) === null || _h === void 0
                        ? void 0
                        : _h[0];
                /* base58 to hex */
                holderPublicKey = buffer_1.Buffer.from(
                    base_58_1.default.decode(
                        verificationMethod === null || verificationMethod === void 0
                            ? void 0
                            : verificationMethod.publicKeyBase58
                    )
                ).toString('hex');
            } else if (
                holder === null || holder === void 0 ? void 0 : holder.startsWith('did:ethr')
            ) {
                holderPublicKey =
                    holder === null || holder === void 0
                        ? void 0
                        : holder.replace('did:ethr:0x', '');
            }
        }
        if (!issuerPublicKey) throw new Error(errors_1.default.NO_ISSUER_PUBLIC_KEY);
        if (!holderPublicKey) throw new Error(errors_1.default.NO_HOLDER_PUBLIC_KEY);
        /* remove selectiveDisclosureMetaData */
        let credentialSubject = Object.assign({}, vc.credentialSubject);
        delete credentialSubject.selectiveDisclosureMetaData;
        const mask =
            ((_k =
                (_j = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null ||
                _j === void 0
                    ? void 0
                    : _j.selectiveDisclosureMetaData) === null || _k === void 0
                ? void 0
                : _k.mask) || {};
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
            const verified = utils_1.default.signature[type].verify({
                data: maskCredential,
                signature:
                    (_m =
                        (_l = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) ===
                            null || _l === void 0
                            ? void 0
                            : _l.selectiveDisclosureMetaData) === null || _m === void 0
                        ? void 0
                        : _m.proof,
                publicKey: issuerPublicKey
            });
            return { verified };
        } catch (error) {
            throw Error(error || errors_1.default.INVALID_VC_SELECTIVE_DISCLOSURE_PROOF);
        }
    }
    if (type === 'key') {
        suite = new ed25519_signature_2018_1.Ed25519Signature2018();
    } else if (type === 'ethr') {
        suite = new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019();
    }
    /* default credential verification */
    try {
        return await vc_js_1.verifiable.credential.verify({
            credential: vc,
            format: ['vc'],
            documentLoader,
            suite
        });
    } catch (error) {
        throw new Error(error || errors_1.default.INVALID_VC_PROOF);
    }
};
exports.default = { create, verify };
//# sourceMappingURL=credential.js.map
