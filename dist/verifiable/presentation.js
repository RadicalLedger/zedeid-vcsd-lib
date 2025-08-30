"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ecdsa_secp256k1_signature_2019_1 = require("@bloomprotocol/ecdsa-secp256k1-signature-2019");
const ed25519_signature_2018_1 = require("@transmute/ed25519-signature-2018");
const vc_js_1 = require("@transmute/vc.js");
const errors_1 = __importDefault(require("../errors"));
const functions_1 = require("../functions");
const utils_1 = __importDefault(require("../utils"));
const credential_1 = __importDefault(require("./credential"));
const ecdsa_secp256k1_verification_key_2019_1 = require("@bloomprotocol/ecdsa-secp256k1-verification-key-2019");
/**
 * Generates a signed presentation for given verifiable credentials using a private key.
 *
 * @param {string} holderPrivateKey - issuer's private key in hex.
 * @param {DocumentLoader} documentLoader - load the document for the given DID.
 * @param {VerifiableCredential[]} verifiableCredential - array of verifiable credentials
 * @param {Mask[]} mask - array of mask credentials for each verifiable credential in key pair format or an empty object.
 * @param {string} issuanceDate - issuance date in ISO format YYYY-MM-DDTHH:mm:ss
 * @param {string} challenge - random string ( eg: fcc8b78e-ecca-426a-a69f-8e7c927b845f )
 * @param {string} domain - domain value ( eg: www.example.com )
 * @param {Suite} suite - crypto suit used to create the verifiable credential.
 *
 * @return {VerifiablePresentation} - signed verifiable presentation of the given verifiable credentials.
 */
const create = async ({ suite, challenge = 'fcc8b78e-ecca-426a-a69f-8e7c927b845f', issuanceDate = new Date().toISOString(), domain, documentLoader, holderPrivateKey, verifiableCredential = [], masks = [], didMethod }) => {
    var _a, _b, _c;
    /* extract the did type */
    if (!didMethod) {
        didMethod = ((_b = (_a = (0, functions_1.getKeyValue)(verifiableCredential, 'holder')) === null || _a === void 0 ? void 0 : _a.split(':')) === null || _b === void 0 ? void 0 : _b[1]) || 'key';
    }
    const holderDoc = await (0, functions_1.privateKeyToDoc)(holderPrivateKey, didMethod);
    /* create masked vc signed by holder */
    const maskedCredentials = await Promise.all(verifiableCredential.map((vc, index) => new Promise((resolve) => {
        const mask = masks[index];
        /* remove selectiveDisclosureMetaData */
        const credentialSubject = Object.assign({}, vc.credentialSubject);
        delete credentialSubject.selectiveDisclosureMetaData;
        /* create a fully masked and selectively masked credential subject */
        const { maskedClaims, maskedMasks } = utils_1.default.mask.create({
            mask,
            credentialSubject,
            holderPublicKey: holderDoc === null || holderDoc === void 0 ? void 0 : holderDoc.publicKey
        });
        /* update credential subject with masked claims */
        vc.credentialSubject = Object.assign(Object.assign({}, vc.credentialSubject), maskedClaims);
        /* add selective disclosure meta data to the credential subject */
        if (!vc.credentialSubject['selectiveDisclosureMetaData'])
            vc.credentialSubject['selectiveDisclosureMetaData'] = {};
        vc.credentialSubject['selectiveDisclosureMetaData']['mask'] = maskedMasks;
        /* delete vc.js proof since the data is altered by masking */
        // delete vc.proof;
        return resolve(vc);
    })));
    /* if a suite is not given use the default */
    if (!suite) {
        const keyPairIssuer = await (0, functions_1.getVerificationKey)({
            seed: holderPrivateKey,
            didMethod
        });
        if (didMethod === 'key') {
            suite = new ed25519_signature_2018_1.Ed25519Signature2018({
                key: keyPairIssuer,
                date: issuanceDate
            });
        }
        else if (didMethod === 'ethr' || didMethod === 'moon') {
            suite = new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019({
                key: keyPairIssuer,
                date: issuanceDate
            });
        }
    }
    const presentation = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: maskedCredentials,
        holder: holderDoc === null || holderDoc === void 0 ? void 0 : holderDoc.DID
    };
    /* create the verifiable presentation */
    const result = await vc_js_1.verifiable.presentation.create({
        presentation,
        format: ['vp'],
        documentLoader,
        challenge,
        domain,
        suite
    });
    return ((_c = result === null || result === void 0 ? void 0 : result.items) === null || _c === void 0 ? void 0 : _c[0]) || null;
};
/**
 * Verify a signed verifiable credential
 *
 * @param {Suite} suite - crypto suit used to create the verifiable credential.
 * @param {string} challenge - random string ( eg: fcc8b78e-ecca-426a-a69f-8e7c927b845f ).
 * @param {string} domain - domain value ( eg: www.example.com ).
 * @param {string} issuerPublicKey - issuer's public key in hex.
 * @param {string} holderPublicKey - holders's public key in hex.
 * @param {DocumentLoader} documentLoader - to load the document for the given DID.
 * @param {VerifiablePresentation} vp - singed credential need to be verified.
 *
 * @return {boolean} - result in boolean format.
 */
const verify = async ({ suite = undefined, challenge = 'fcc8b78e-ecca-426a-a69f-8e7c927b845f', domain, vp, documentLoader, issuerPublicKey, holderPublicKey, didMethod }) => {
    var _a, _b, _c, _d, _e, _f, _g;
    /* extract the did type */
    if (!didMethod) {
        didMethod = ((_b = (_a = (0, functions_1.getKeyValue)(vp, 'holder')) === null || _a === void 0 ? void 0 : _a.split(':')) === null || _b === void 0 ? void 0 : _b[1]) || 'key';
    }
    /* check essential data is present in vp */
    (0, functions_1.checkVpMetaData)(vp);
    /* extract data from verifiable presentation */
    const { verifiableCredential } = vp;
    /* check if any vc has selectiveDisclosureMetaData proof */
    const hasMaskedProof = verifiableCredential.filter((vc) => {
        var _a, _b, _c, _d;
        return (Object.keys((_b = (_a = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _a === void 0 ? void 0 : _a.selectiveDisclosureMetaData) === null || _b === void 0 ? void 0 : _b.mask).length > 0 &&
            ((_d = (_c = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _c === void 0 ? void 0 : _c.selectiveDisclosureMetaData) === null || _d === void 0 ? void 0 : _d.proof));
    }).length > 0;
    /* if available verify vc's manually */
    if (hasMaskedProof) {
        /* verify each verifiable credential */
        for (const vc of verifiableCredential) {
            try {
                const result = await credential_1.default.verify({
                    vc,
                    documentLoader,
                    holderPublicKey,
                    issuerPublicKey,
                    suite,
                    didMethod
                });
                if (!(result === null || result === void 0 ? void 0 : result.verified))
                    throw Error(errors_1.default.INVALID_VC_PROOF);
            }
            catch (e) {
                throw Error(`At least one credential is not valid\n${e.message}`);
            }
        }
        return { verified: true };
    }
    if (didMethod === 'key') {
        suite = new ed25519_signature_2018_1.Ed25519Signature2018();
    }
    else if (didMethod === 'ethr' || didMethod === 'moon') {
        const holderDocument = await documentLoader(vp.holder);
        const verificationMethod = (_c = holderDocument === null || holderDocument === void 0 ? void 0 : holderDocument.document) === null || _c === void 0 ? void 0 : _c.verificationMethod.filter((vm) => {
            return vm.type === 'EcdsaSecp256k1VerificationKey2019';
        });
        if (!holderPublicKey)
            holderPublicKey = (_d = verificationMethod[0]) === null || _d === void 0 ? void 0 : _d.publicKeyHex;
        const key = ecdsa_secp256k1_verification_key_2019_1.EcdsaSecp256k1VerificationKey2019.from({
            controller: (_e = verificationMethod[0]) === null || _e === void 0 ? void 0 : _e.controller,
            id: (_f = verificationMethod[0]) === null || _f === void 0 ? void 0 : _f.id,
            publicKeyHex: (_g = verificationMethod[0]) === null || _g === void 0 ? void 0 : _g.publicKeyHex
        });
        suite = new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019({ key });
    }
    /* default presentation verification */
    const result = await vc_js_1.verifiable.presentation.verify({
        presentation: vp,
        format: ['vp'],
        documentLoader,
        suite,
        challenge,
        domain
    });
    return result === null || result === void 0 ? void 0 : result.presentation;
};
exports.default = { create, verify };
//# sourceMappingURL=presentation.js.map