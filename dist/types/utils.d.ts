import { VC, VP, Claims, Mask } from "./interface";
export declare class Signer {
    readonly publicKey: string;
    readonly privateKey: string;
    constructor(_publicKey: string, _sign: (data: any) => string);
    constructor(_privateKey: string);
    sign(data: any): string;
}
export declare function base64UrlEncode(unencoded: string): string;
export declare function base64UrlDecode(encoded: string): string;
export declare function blind(data: string, key: string): string;
/**
 * Generate masked claim set of a plain claim set
 *
 * @param {Claims} claims - Plain claims.
 * @param {Mask} mask - Mask. Key of claim: true if it should be masked.
 * @param {string} holderPublicKey - Holder's Ethereum public key in hex.
 *
 * @return {Claims}  Masked claims.
 */
export declare function generateMaskedClaims(claims: Claims, mask: Mask, holderPublicKey: string): {
    maskedClaims: Claims;
    mask: Mask;
};
/**
 * Generate fully masked claim set of a partially masked claim set
 *
 * @param {Claims} claims - Partially masked claims.
 * @param {Mask} mask - Mask; Keys and values should be mask or a empty object.
 * @param {string} holderPublicKey - Holder's Ethereum public key in hex.
 *
 * @return {Claims}  Fully masked claims.
 */
export declare function generateFullyMaskedClaims(claims: Claims, mask: Mask, holderPublicKey: string): Claims;
export declare function generateSignature(data: any, privateKey: string): string;
export declare function verifySignature(data: any, signature: string, publicKey: string): boolean;
export declare function checkVcMetaData(vc: VC): void;
export declare function checkVpMetaData(vp: VP): void;
export declare function sortObject(object: any): any;
export declare const ERRORS: Readonly<{
    DID_PUBLIC_KEY_MISMATCH: string;
    INVALID_DID_ERROR: string;
    INVALID_DOCUMENT: string;
    TYPE_NOT_VALID: string;
    NO_ISSUER: string;
    NO_ISSUER_DID: string;
    INVALID_ISSUER_PUBLIC_KEY: string;
    INVALID_ISSUER_PRIVATE_KEY: string;
    NO_ISSUER_PUBLIC_KEY: string;
    NO_SUBJECT: string;
    NO_SUBJECT_DID: string;
    NO_SUBJECT_PUBLIC_KEY: string;
    NO_CLAIMS: string;
    NO_CREDENTIALS: string;
    NO_PROOF_VC: string;
    NO_PROOF_VP: string;
    MASKING_ERROR: string;
    SIGNING_ERROR: string;
    INVALID_HOLDER_PRIVATE_KEY: string;
    INVALID_HOLDER_PUBLIC_KEY: string;
    INVALID_VC_PROOF: string;
    INVALID_VP_PROOF: string;
    INVALID_SIGNATURE: string;
}>;
