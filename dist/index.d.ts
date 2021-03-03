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
export declare function issue(claims: Claims, signerPrivateKey: string, holderPublicKey: string): VC;
export declare function present(credentials: VC[], masks: Mask[], holderPrivateKey: string): VP;
export declare function verify(vp: VP, signerPublicKeys: string[], holderPublicKey: string): Promise<boolean>;
export declare function verifyVC(vc: VC, signerPublicKey: string, holderPublicKey: string): Promise<boolean>;
export declare function verifyVcSignature(claims: Claims, mask: Mask | undefined, proof: string, signerPublicKey: string, holderPublicKey: string): boolean;
export declare function verifyVpSignature(credentials: VC[], proof: string, holderPublicKey: string): boolean;
export declare function checkVcMetaData(vc: VC): void;
export declare function checkVpMetaData(vp: VP): void;
export { base64UrlEncode, base64UrlDecode } from './utils';
