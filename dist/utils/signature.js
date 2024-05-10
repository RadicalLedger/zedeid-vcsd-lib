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
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const sha_js_1 = __importDefault(require("sha.js"));
const errors_1 = __importDefault(require("../errors"));
const utils_1 = __importDefault(require("../utils"));
const buffer_1 = require("buffer");
const secp256k1 = __importStar(require("secp256k1"));
/**
 * Generates a hex signature proof for a given verifiable credential or presentation
 *
 * @param {any} data - verifiable credential or presentation in json format.
 * @param {string} privateKey - private key of the issuer of the verifiable credential or presentation.
 *
 * @returns {string} - signature proof as a hex string.
 */
const generateKeySignature = ({ data, privateKey }) => {
    const ed = new utils_1.default.ed25519();
    const privateKeyBuffer = buffer_1.Buffer.from(privateKey, 'hex');
    const dataString = JSON.stringify(data);
    const dataStringHash = new sha_js_1.default.sha256().update(dataString).digest('hex');
    const dataStringHashBuffer = buffer_1.Buffer.from(dataStringHash, 'hex');
    const signature = ed.sign(dataStringHashBuffer, privateKeyBuffer).toHex();
    return signature;
};
/**
 * Verify the given signature proof of a verifiable credential or presentation
 *
 * @param {MaskCredential | MaskPresentation} data - keys and values should be mask or a empty object.
 * @param {string} signature - signature proof as a hex string.
 * @param {string} publicKey - issuer's / holder's public key in hex.
 *
 * @return {boolean}  validated result in boolean format.
 */
const verifyKeySignature = ({ data, signature, publicKey }) => {
    try {
        const ed = new utils_1.default.ed25519();
        const vcString = JSON.stringify(data);
        const vcHash = new sha_js_1.default.sha256().update(vcString).digest('hex');
        const vcHashBuffer = buffer_1.Buffer.from(vcHash, 'hex');
        const result = ed.verify(signature, vcHashBuffer, publicKey);
        if (result === true)
            return result;
        throw Error(errors_1.default.FAILED_MASK_VERIFICATION);
    }
    catch (error) {
        throw Error(errors_1.default.INVALID_SIGNATURE);
    }
};
/**
 * Generates a hex signature proof for a given verifiable credential or presentation
 *
 * @param {any} data - verifiable credential or presentation in json format.
 * @param {string} privateKey - private key of the issuer of the verifiable credential or presentation.
 *
 * @returns {string} - signature proof as a hex string.
 */
const generateEthrSignature = ({ data, privateKey }) => {
    const privateKeyBuffer = buffer_1.Buffer.from(privateKey, 'hex');
    const dataString = JSON.stringify(data);
    const dataStringHash = new sha_js_1.default.sha256().update(dataString).digest('hex');
    const dataStringHashBuffer = buffer_1.Buffer.from(dataStringHash, 'hex');
    const signature = buffer_1.Buffer.from(secp256k1.ecdsaSign(dataStringHashBuffer, privateKeyBuffer).signature).toString('hex');
    return signature;
};
/**
 * Verify the given signature proof of a verifiable credential or presentation
 *
 * @param {MaskCredential | MaskPresentation} data - keys and values should be mask or a empty object.
 * @param {string} signature - signature proof as a hex string.
 * @param {string} publicKey - issuer's / holder's public key in hex.
 *
 * @return {boolean}  validated result in boolean format.
 */
const verifyEthrSignature = ({ data, signature, publicKey }) => {
    try {
        const vcString = JSON.stringify(data);
        const vcHash = new sha_js_1.default.sha256().update(vcString).digest('hex');
        const vcHashBuffer = buffer_1.Buffer.from(vcHash, 'hex');
        const dataStringBuffer = new Uint8Array(buffer_1.Buffer.from(signature, 'hex'));
        const publicKeyBuffer = new Uint8Array(buffer_1.Buffer.from(publicKey, 'hex'));
        const result = secp256k1.ecdsaVerify(dataStringBuffer, vcHashBuffer, publicKeyBuffer);
        if (result === true)
            return result;
        throw Error(errors_1.default.FAILED_MASK_VERIFICATION);
    }
    catch (error) {
        throw Error(errors_1.default.INVALID_SIGNATURE);
    }
};
exports.default = {
    key: {
        generate: generateKeySignature,
        verify: verifyKeySignature
    },
    ethr: {
        generate: generateEthrSignature,
        verify: verifyEthrSignature
    },
    moon: {
        generate: generateEthrSignature,
        verify: verifyEthrSignature
    }
};
//# sourceMappingURL=signature.js.map