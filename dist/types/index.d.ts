export interface Claims {
    [key: string]: string;
}
export interface Mask {
    [key: string]: boolean;
}
export interface VC {
    context?: string;
    issuer: {
        did: string;
        publicKey: string;
    };
    subject: {
        did: string;
        publicKey: string;
    };
    type: string;
    claims: Claims;
    proof: string;
    iat?: string;
    exp?: string;
    mask?: Mask;
}
export interface VP {
    context?: string;
    subject: {
        did: string;
        publicKey: string;
    };
    type: string;
    credentials: Array<VC>;
    proof: string;
}
/**
 * Generates a signed credential for given claims.
 *
 * @param {Claims} claims - Claims need to be signed as key value pairs.
 * @param {string} signerPrivateKey - Signer's Ethereum private key in hex.
 * @param {string} holderPublicKey - Holder's Ethereum public key in hex.
 *
 * @return {VC} Signed verifiable credential of the given claims.
 */
export declare function issue(claims: Claims, signerPrivateKey: string, holderPublicKey: string): VC;
/**
 * Generates a signed presentation for given verifiable credentials.
 *
 * @param {VC[]} credentials - List of verifiable credentials to be presented.
 * @param {Mask[]} masks - List of mask object defining what attributes of the corresponding credentials to be masked.
 * @param {string} holderPrivateKey - Holder's Ethereum private key in hex.
 *
 * @return {VP} Signed verifiable presentation of the given verifiable credentials.
 */
export declare function present(credentials: VC[], masks: Mask[], holderPrivateKey: string): VP;
/**
 * Verify the validity of a verifiable presentation.
 *
 * @param {VP} vp - Verifiable presentation need to be validated.
 * @param {string[]} signerPublicKeys - List of public keys of the signers of which the credentials in the presentation is signed by.
 * @param {string} holderPublicKey - Holder's Ethereum public key in hex.
 *
 * @return {Promise<boolean>}  A Promise which resolves to true if the presentation is valid.
 */
export declare function verify(vp: VP, signerPublicKeys: string[], holderPublicKey: string): Promise<boolean>;
export declare function verifyVC(vc: VC, signerPublicKey: string, holderPublicKey: string): Promise<boolean>;
export declare function verifyVcSignature(claims: Claims, mask: Mask | undefined, proof: string, signerPublicKey: string, holderPublicKey: string): boolean;
export declare function verifyVpSignature(credentials: VC[], proof: string, holderPublicKey: string): boolean;
export declare function checkVcMetaData(vc: VC): void;
export declare function checkVpMetaData(vp: VP): void;
export { base64UrlEncode, base64UrlDecode, ERRORS } from './utils';
