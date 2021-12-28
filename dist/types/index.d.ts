import { Signer } from './utils';
import { Claims, Mask, VC, VP } from './interface';
/**
 * Generates a signed credential for given claims using a private key.
 *
 * @param {string} issuerPrivateKey - issuer's Ethereum private key in hex.
 * @param {Claims} claims - Claims need to be signed as key value pairs.
 * @param {string} holderPublicKey - Holder's Ethereum public key in hex.
 *
 * @return {VC} Signed verifiable credential of the given claims.
 */
export declare function issue(issuerPrivateKey: string, claims: Claims, holderPublicKey: string): VC;
/**
 * Generates a signed credential for given claims using a signer object.
 *
 * @param {string} issuer - issuer's signer object.
 * @param {Claims} claims - Claims need to be signed as key value pairs.
 * @param {string} holderPublicKey - Holder's Ethereum public key in hex.
 *
 * @return {VC} Signed verifiable credential of the given claims.
 */
export declare function issue(issuer: Signer, claims: Claims, holderPublicKey: string): VC;
/**
 * Generates a signed presentation for given verifiable credentials using a private key.
 *
 * @param {string} holderPrivateKey - Holder's Ethereum private key in hex.
 * @param {VC[]} credentials - List of verifiable credentials to be presented.
 * @param {Mask[]} masks - List of mask object defining what attributes of the corresponding credentials to be masked.
 *
 * @return {VP} Signed verifiable presentation of the given verifiable credentials.
 */
export declare function present(holderPrivateKey: string, credentials: VC[], masks: Mask[]): VP;
/**
 * Generates a signed presentation for given verifiable credentials using a signer object.
 *
 * @param {string} holder - Holder's signer object.
 * @param {VC[]} credentials - List of verifiable credentials to be presented.
 * @param {Mask[]} masks - List of mask object defining what attributes of the corresponding credentials to be masked.
 *
 * @return {VP} Signed verifiable presentation of the given verifiable credentials.
 */
export declare function present(holder: Signer, credentials: VC[], masks: Mask[]): VP;
/**
 * Verify the validity of a verifiable presentation.
 *
 * @param {VP} vp - Verifiable presentation need to be validated.
 * @param {string[]} issuerPublicKeys - List of public keys of the issuers of which the credentials in the presentation is signed by.
 * @param {string} holderPublicKey - Holder's Ethereum public key in hex.
 *
 * @return {boolean}  True if the presentation is valid.
 */
export declare function verify(vp: VP, issuerPublicKeys: string[], holderPublicKey: string): boolean;
/**
 * Verify the validity of a verifiable credential.
 *
 * @param {VC} vc - Verifiable credential need to be validated.
 * @param {string[]} issuerPublicKey - List of public keys of the issuers of which the credentials in the presentation is signed by.
 * @param {string} holderPublicKey - Holder's Ethereum public key in hex.
 *
 * @return {boolean}  True if the presentation is valid.
 */
export declare function verifyVC(vc: VC, issuerPublicKey: string, holderPublicKey: string): boolean;
export { base64UrlEncode, base64UrlDecode, ERRORS, Signer } from './utils';
export { Claims, Mask, VC, VP } from './interface';
