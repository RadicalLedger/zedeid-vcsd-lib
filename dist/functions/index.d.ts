import { VerifiableCredential } from '@transmute/vc.js/dist/types/VerifiableCredential';
import { VerifiablePresentation } from '@transmute/vc.js/dist/types/VerifiablePresentation';
import { DIDMethods } from 'utils.type';
declare function base64UrlEncode(unencoded: string): string;
declare function base64UrlDecode(encoded: string): string;
declare function blind(data: string, key: string): string;
declare function getVerificationKey({ seed, VerificationMethodId, didMethod }: {
    seed: string;
    VerificationMethodId?: string;
    didMethod: DIDMethods;
}): Promise<any>;
declare const _default: {
    base64UrlEncode: typeof base64UrlEncode;
    base64UrlDecode: typeof base64UrlDecode;
    blind: typeof blind;
    sortObject: (object: any) => {};
    privateKeyToDoc: (privateKey: string, didMethod?: DIDMethods) => Promise<{
        privateKey: string;
        publicKey: string;
        DID: string;
    }>;
    checkVcMetaData: (vc: VerifiableCredential) => void;
    checkVpMetaData: (vp: VerifiablePresentation) => void;
    getVerificationKey: typeof getVerificationKey;
    getKeyValue: (obj: any, key: string) => any;
};
export default _default;
