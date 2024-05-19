import verifiable from './verifiable';
import utils from './utils';
import functions from './functions';
declare const VCSD: {
    verifiable: {
        credential: {
            create: ({ issuerPrivateKey, issuanceDate, documentLoader, credential, suite, didMethod }: import("./types/credential.type").CreateProps) => Promise<import("@transmute/vc.js/dist/types/VerifiableCredential").VerifiableCredential>;
            verify: ({ suite, vc, documentLoader, issuerPublicKey, holderPublicKey, didMethod }: import("./types/credential.type").VerifyProps) => Promise<{
                verified: any;
            }>;
        };
        presentation: {
            create: ({ suite, challenge, issuanceDate, domain, documentLoader, holderPrivateKey, holderDID, verifiableCredential, masks, didMethod }: import("./types/presentation.type").CreateProps) => Promise<import("@transmute/vc.js/dist/types/VerifiablePresentation").VerifiablePresentation>;
            verify: ({ suite, challenge, domain, vp, documentLoader, issuerPublicKey, holderPublicKey, didMethod }: import("./types/presentation.type").VerifyProps) => Promise<import("@transmute/vc.js/dist/types").VerificationResult>;
        };
    };
    utils: {
        mask: {
            create: ({ mask, credentialSubject, holderPublicKey }: import("./types/utils.type").MaskProps) => {
                maskedClaims: {};
                maskedMasks: {};
            };
            full: ({ mask, credentialSubject, holderPublicKey }: import("./types/utils.type").MaskProps) => import("./types/utils.type").Claims;
        };
        signature: {
            key: {
                generate: ({ data, privateKey }: import("./types/utils.type").GenerateSignatureProps) => string;
                verify: ({ data, signature, publicKey }: import("./types/utils.type").VerifySignatureProps) => any;
            };
            ethr: {
                generate: ({ data, privateKey }: import("./types/utils.type").GenerateSignatureProps) => string;
                verify: ({ data, signature, publicKey }: import("./types/utils.type").VerifySignatureProps) => true;
            };
            moon: {
                generate: ({ data, privateKey }: import("./types/utils.type").GenerateSignatureProps) => string;
                verify: ({ data, signature, publicKey }: import("./types/utils.type").VerifySignatureProps) => true;
            };
        };
        ed25519: typeof import("./utils/ed25519").default;
        secp256k1: typeof import("secp256k1");
    };
    functions: {
        base64UrlEncode: (unencoded: string) => string;
        base64UrlDecode: (encoded: string) => string;
        blind: (data: string, key: string) => string;
        sortObject: (object: any) => {};
        privateKeyToDoc: (privateKey: string, didMethod?: import("./types/utils.type").DIDMethods) => Promise<{
            privateKey: string;
            publicKey: string;
            DID: string;
        }>;
        checkVcMetaData: (vc: import("@transmute/vc.js/dist/types/VerifiableCredential").VerifiableCredential) => void;
        checkVpMetaData: (vp: import("@transmute/vc.js/dist/types/VerifiablePresentation").VerifiablePresentation) => void;
        getVerificationKey: ({ seed, VerificationMethodId, didMethod }: {
            seed: string;
            VerificationMethodId?: string;
            didMethod: import("./types/utils.type").DIDMethods;
        }) => Promise<any>;
        getKeyValue: (obj: any, key: string) => any;
    };
};
export { verifiable, utils, functions };
export default VCSD;
