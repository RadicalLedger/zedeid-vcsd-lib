import * as secp256k1 from 'secp256k1';
import * as _transmute_vc_js_dist_types_VerifiablePresentation from '@transmute/vc.js/dist/types/VerifiablePresentation';
import { VerifiablePresentation } from '@transmute/vc.js/dist/types/VerifiablePresentation';
import { Suite } from '@transmute/vc.js/dist/types/Suite';
import { DocumentLoader } from '@transmute/vc.js/dist/types/DocumentLoader';
import * as _transmute_vc_js_dist_types_VerifiableCredential from '@transmute/vc.js/dist/types/VerifiableCredential';
import { VerifiableCredential } from '@transmute/vc.js/dist/types/VerifiableCredential';

declare class Ed25519 {
    private ed;
    constructor();
    /**
     * sign message with private key
     *
     * @param message - Buffer | Uint8Array
     * @param privateKey - Buffer | Uint8Array
     *
     * @returns - Signed buffer
     */
    sign(message: Buffer | Uint8Array, privateKey: Buffer | Uint8Array): any;
    /**
     * verify message with public key
     *
     * @param signature - Buffer | Uint8Array | Hex
     * @param message - Buffer | Uint8Array
     * @param publicKey - Hex string
     *
     * @returns - boolean
     */
    verify(signature: Buffer | Uint8Array | string, message: Buffer | Uint8Array, publicKey: string): any;
}

interface Credential {
    '@context': any[];
    id: string;
    issuanceDate: string;
    type: string | string[];
    issuer: string;
    credentialSubject: any;
    mask?: any;
}

interface CreateProps$1 {
    issuanceDate?: string;
    issuerPrivateKey: string;
    holderPublicKey?: string;
    documentLoader: DocumentLoader;
    credential: Credential;
    suite?: Suite;
    didMethod?: DIDMethods;
}

interface VerifyProps$1 {
    issuerPublicKey?: string;
    holderPublicKey?: string;
    documentLoader: DocumentLoader;
    vc: VerifiableCredential;
    suite?: Suite;
    didMethod?: DIDMethods;
}

interface Claims {
    [key: string | number]: any;
}

interface Mask {
    [key: string | number]: any;
}

interface MaskProps {
    mask: Mask;
    credentialSubject: Claims;
    holderPublicKey: string;
}

interface VerifySignatureProps {
    data: any;
    signature: string;
    publicKey: string;
}

interface GenerateSignatureProps {
    data: any;
    privateKey: string;
}

type DIDMethods = 'key' | 'ethr';

interface CreateProps {
    holderPrivateKey: string;
    documentLoader: DocumentLoader;
    verifiableCredential: VerifiableCredential[];
    challenge?: string;
    domain?: string;
    suite?: Suite;
    issuanceDate?: string;
    masks?: Mask[];
    didMethod?: DIDMethods;
}

interface VerifyProps {
    issuerPublicKey?: string;
    holderPublicKey?: string;
    documentLoader: DocumentLoader;
    vp: VerifiablePresentation;
    challenge?: string;
    domain?: string;
    suite?: Suite;
    didMethod?: DIDMethods;
}

declare const _default$1: {
    credential: {
        create: ({ issuerPrivateKey, issuanceDate, documentLoader, credential, suite, didMethod }: CreateProps$1) => Promise<_transmute_vc_js_dist_types_VerifiableCredential.VerifiableCredential>;
        verify: ({ suite, vc, documentLoader, issuerPublicKey, holderPublicKey, didMethod }: VerifyProps$1) => Promise<{
            verified: any;
        }>;
    };
    presentation: {
        create: ({ suite, challenge, issuanceDate, domain, documentLoader, holderPrivateKey, verifiableCredential, masks, didMethod }: CreateProps) => Promise<_transmute_vc_js_dist_types_VerifiablePresentation.VerifiablePresentation>;
        verify: ({ suite, challenge, domain, vp, documentLoader, issuerPublicKey, holderPublicKey, didMethod }: VerifyProps) => Promise<any>;
    };
};

declare const _default: {
    mask: {
        create: ({ mask, credentialSubject, holderPublicKey }: MaskProps) => {
            maskedClaims: {};
            maskedMasks: {};
        };
        full: ({ mask, credentialSubject, holderPublicKey }: MaskProps) => Claims;
    };
    signature: {
        key: {
            generate: ({ data, privateKey }: GenerateSignatureProps) => string;
            verify: ({ data, signature, publicKey }: VerifySignatureProps) => any;
        };
        ethr: {
            generate: ({ data, privateKey }: GenerateSignatureProps) => string;
            verify: ({ data, signature, publicKey }: VerifySignatureProps) => true;
        };
    };
    ed25519: typeof Ed25519;
    secp256k1: typeof secp256k1;
};

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

declare const functions_base64UrlDecode: typeof base64UrlDecode;
declare const functions_base64UrlEncode: typeof base64UrlEncode;
declare const functions_blind: typeof blind;
declare const functions_checkVcMetaData: typeof checkVcMetaData;
declare const functions_checkVpMetaData: typeof checkVpMetaData;
declare const functions_getFullPrivateKeyBs58: typeof getFullPrivateKeyBs58;
declare const functions_getKeyValue: typeof getKeyValue;
declare const functions_getVerificationKey: typeof getVerificationKey;
declare const functions_privateKeyToDoc: typeof privateKeyToDoc;
declare const functions_sortObject: typeof sortObject;
declare namespace functions {
  export { functions_base64UrlDecode as base64UrlDecode, functions_base64UrlEncode as base64UrlEncode, functions_blind as blind, functions_checkVcMetaData as checkVcMetaData, functions_checkVpMetaData as checkVpMetaData, functions_getFullPrivateKeyBs58 as getFullPrivateKeyBs58, functions_getKeyValue as getKeyValue, functions_getVerificationKey as getVerificationKey, functions_privateKeyToDoc as privateKeyToDoc, functions_sortObject as sortObject };
}

declare const VCSD: {
    verifiable: {
        credential: {
            create: ({ issuerPrivateKey, issuanceDate, documentLoader, credential, suite, didMethod }: CreateProps$1) => Promise<_transmute_vc_js_dist_types_VerifiableCredential.VerifiableCredential>;
            verify: ({ suite, vc, documentLoader, issuerPublicKey, holderPublicKey, didMethod }: VerifyProps$1) => Promise<{
                verified: any;
            }>;
        };
        presentation: {
            create: ({ suite, challenge, issuanceDate, domain, documentLoader, holderPrivateKey, verifiableCredential, masks, didMethod }: CreateProps) => Promise<_transmute_vc_js_dist_types_VerifiablePresentation.VerifiablePresentation>;
            verify: ({ suite, challenge, domain, vp, documentLoader, issuerPublicKey, holderPublicKey, didMethod }: VerifyProps) => Promise<any>;
        };
    };
    utils: {
        mask: {
            create: ({ mask, credentialSubject, holderPublicKey }: MaskProps) => {
                maskedClaims: {};
                maskedMasks: {};
            };
            full: ({ mask, credentialSubject, holderPublicKey }: MaskProps) => Claims;
        };
        signature: {
            key: {
                generate: ({ data, privateKey }: GenerateSignatureProps) => string;
                verify: ({ data, signature, publicKey }: VerifySignatureProps) => any;
            };
            ethr: {
                generate: ({ data, privateKey }: GenerateSignatureProps) => string;
                verify: ({ data, signature, publicKey }: VerifySignatureProps) => true;
            };
        };
        ed25519: typeof Ed25519;
        secp256k1: typeof secp256k1;
    };
    functions: typeof functions;
};

export { VCSD as default, functions, _default as utils, _default$1 as verifiable };
