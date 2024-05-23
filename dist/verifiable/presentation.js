"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ed25519_signature_2018_1 = require("@transmute/ed25519-signature-2018");
const vc_js_1 = require("@transmute/vc.js");
const errors_1 = __importDefault(require("../errors"));
const utils_1 = __importDefault(require("../utils"));
const functions_1 = __importDefault(require("../functions"));
const credential_1 = __importDefault(require("./credential"));
const ecdsa_secp256k1_signature_2019_1 = require("@bloomprotocol/ecdsa-secp256k1-signature-2019");
const base_58_1 = __importDefault(require("base-58"));
const edca_secp256k1_verification_2019_1 = require("edca-secp256k1-verification-2019");
/**
 * Generates a signed presentation for given verifiable credentials using a private key.
 *
 * @param {string} holderPrivateKey - issuer's private key in hex.
 * @param {string} holderDID - holder's DID
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
const create = async ({ suite, challenge = 'fcc8b78e-ecca-426a-a69f-8e7c927b845f', issuanceDate = new Date().toISOString(), domain, documentLoader, holderPrivateKey, holderDID, verifiableCredential = [], masks = [], didMethod }) => {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r;
    /* extract the did type */
    if (!didMethod) {
        didMethod = ((_b = (_a = functions_1.default.getKeyValue(verifiableCredential, 'holder')) === null || _a === void 0 ? void 0 : _a.split(':')) === null || _b === void 0 ? void 0 : _b[1]) || 'key';
    }
    if ((didMethod == 'moon' || didMethod === 'ethr') && !holderDID) {
        throw new Error(errors_1.default.NO_HOLDER_DID);
    }
    let holderDoc;
    if (didMethod === 'key' && !holderDID) {
        holderDoc = await functions_1.default.privateKeyToDoc(holderPrivateKey, didMethod);
    }
    let verificationKey;
    let holderPublicKey;
    let verificationMethod;
    if (holderDID) {
        const holderDocument = await documentLoader(holderDID);
        if ((_c = holderDocument === null || holderDocument === void 0 ? void 0 : holderDocument.document) === null || _c === void 0 ? void 0 : _c.verificationMethod) {
            verificationMethod = (_d = holderDocument === null || holderDocument === void 0 ? void 0 : holderDocument.document) === null || _d === void 0 ? void 0 : _d.verificationMethod.filter((vm) => vm.type === 'EcdsaSecp256k1VerificationKey2019' ||
                vm.type === 'Ed25519VerificationKey2018');
            switch ((_e = verificationMethod[0]) === null || _e === void 0 ? void 0 : _e.type) {
                case 'Ed25519VerificationKey2018':
                    verificationKey = await ed25519_signature_2018_1.Ed25519VerificationKey2018.from({
                        controller: (_f = verificationMethod[0]) === null || _f === void 0 ? void 0 : _f.controller,
                        id: (_g = verificationMethod[0]) === null || _g === void 0 ? void 0 : _g.id,
                        type: (_h = verificationMethod[0]) === null || _h === void 0 ? void 0 : _h.type,
                        publicKeyBase58: (_j = verificationMethod[0]) === null || _j === void 0 ? void 0 : _j.publicKeyBase58,
                        privateKeyBase58: base_58_1.default.encode(Buffer.from(holderPrivateKey, 'hex'))
                    });
                    holderPublicKey = Buffer.from(base_58_1.default.decode((_k = verificationMethod[0]) === null || _k === void 0 ? void 0 : _k.publicKeyBase58)).toString('hex');
                    break;
                case 'EcdsaSecp256k1VerificationKey2019':
                    verificationKey = edca_secp256k1_verification_2019_1.EcdsaSecp256k1VerificationKey2019.from({
                        controller: (_l = verificationMethod[0]) === null || _l === void 0 ? void 0 : _l.controller,
                        id: (_m = verificationMethod[0]) === null || _m === void 0 ? void 0 : _m.id,
                        publicKeyHex: (_o = verificationMethod[0]) === null || _o === void 0 ? void 0 : _o.publicKeyHex,
                        privateKeyHex: holderPrivateKey
                    });
                    holderPublicKey = (_p = verificationMethod[0]) === null || _p === void 0 ? void 0 : _p.publicKeyHex;
                    break;
            }
            if (!verificationKey) {
                throw new Error(errors_1.default.NO_VERIFICATION_METHOD);
            }
        }
        else {
            throw new Error(errors_1.default.NO_HOLDER_PUBLIC_KEY);
        }
    }
    /* create masked vc signed by holder */
    const maskedCredentials = await Promise.all(verifiableCredential.map((vc, index) => new Promise(async (resolve) => {
        const mask = masks[index];
        /* remove selectiveDisclosureMetaData */
        let credentialSubject = Object.assign({}, vc.credentialSubject);
        delete credentialSubject.selectiveDisclosureMetaData;
        /* create a fully masked and selectively masked credential subject */
        const { maskedClaims, maskedMasks } = utils_1.default.mask.create({
            mask,
            credentialSubject,
            holderPublicKey: (holderDoc === null || holderDoc === void 0 ? void 0 : holderDoc.publicKey) || holderPublicKey
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
        switch ((_q = verificationMethod[0]) === null || _q === void 0 ? void 0 : _q.type) {
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
    const presentation = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: maskedCredentials,
        holder: (holderDoc === null || holderDoc === void 0 ? void 0 : holderDoc.DID) || holderDID
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
    return ((_r = result === null || result === void 0 ? void 0 : result.items) === null || _r === void 0 ? void 0 : _r[0]) || null;
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
const verify = async ({ suite = undefined, challenge = 'fcc8b78e-ecca-426a-a69f-8e7c927b845f', domain, vp, documentLoader, issuerPublicKey, holderPublicKey }) => {
    /* extract the did type */
    /* check essential data is present in vp */
    functions_1.default.checkVpMetaData(vp);
    /* extract data from verifiable presentation */
    const { verifiableCredential } = vp;
    /* verify each verifiable credential */
    for (const vc of verifiableCredential) {
        try {
            const result = await credential_1.default.verify({
                vc,
                documentLoader,
                issuerPublicKey,
                holderPublicKey,
                suite
            });
            if (!(result === null || result === void 0 ? void 0 : result.verified))
                throw Error(errors_1.default.INVALID_VC_PROOF);
        }
        catch (e) {
            throw Error(`At least one credential is not valid\n${e.message}`);
        }
    }
    /* check if any vc has selectiveDisclosureMetaData proof */
    if (verifiableCredential.filter((vc) => {
        var _a;
        return !!((_a = vc === null || vc === void 0 ? void 0 : vc.credentialSubject) === null || _a === void 0 ? void 0 : _a.selectiveDisclosureMetaData);
    }).length > 0) {
        return { verified: true };
    }
    switch (vp.proof.type) {
        case 'Ed25519Signature2018':
            suite = new ed25519_signature_2018_1.Ed25519Signature2018();
            break;
        case 'EcdsaSecp256k1Signature2019':
            suite = new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019();
            break;
    }
    /* default presentation verification */
    return await vc_js_1.verifiable.presentation.verify({
        presentation: vp,
        format: ['vp'],
        documentLoader,
        suite,
        challenge,
        domain
    });
};
exports.default = { create, verify };
//# sourceMappingURL=presentation.js.map