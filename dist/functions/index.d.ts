import { VerifiableCredential } from '@transmute/vc.js/dist/types/VerifiableCredential';
import { VerifiablePresentation } from '@transmute/vc.js/dist/types/VerifiablePresentation';
import { DIDMethods } from '../types/utils';
declare function base64UrlEncode(unencoded: string): string;
declare function base64UrlDecode(encoded: string): string;
declare function blind(data: string, key: string): string;
declare const sortObject: (object: any) => {};
declare const privateKeyToDoc: (privateKey: string, didMethod?: DIDMethods) => Promise<{
    privateKey: string;
    publicKey: string;
    DID: string;
}>;
declare function getVerificationKey({ seed, didMethod }: {
    seed: string;
    didMethod: DIDMethods;
}): Promise<any>;
declare const checkVcMetaData: (vc: VerifiableCredential) => void;
declare const checkVpMetaData: (vp: VerifiablePresentation) => void;
declare const getKeyValue: (obj: any, key: string) => any;
declare const getFullPrivateKeyBs58: (privateKey: string, publicKey: string) => string;
export { base64UrlEncode, base64UrlDecode, blind, sortObject, privateKeyToDoc, checkVcMetaData, checkVpMetaData, getVerificationKey, getKeyValue, getFullPrivateKeyBs58 };
