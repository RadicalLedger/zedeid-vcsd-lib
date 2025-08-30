import verifiable from './verifiable';
import utils from './utils';
import * as functions from './functions';
declare const VCSD: {
    verifiable: {
        credential: {
            create: ({ issuerPrivateKey, issuanceDate, documentLoader, credential, suite, didMethod }: import("./types/credential").CreateProps) => Promise<import("@transmute/vc.js/dist/types/VerifiableCredential").VerifiableCredential>;
            verify: ({ suite, vc, documentLoader, issuerPublicKey, holderPublicKey, didMethod }: import("./types/credential").VerifyProps) => Promise<{
                verified: any;
            }>;
        };
        presentation: {
            create: ({ suite, challenge, issuanceDate, domain, documentLoader, holderPrivateKey, verifiableCredential, masks, didMethod }: import("./types/presentation").CreateProps) => Promise<import("@transmute/vc.js/dist/types/VerifiablePresentation").VerifiablePresentation>;
            verify: ({ suite, challenge, domain, vp, documentLoader, issuerPublicKey, holderPublicKey, didMethod }: import("./types/presentation").VerifyProps) => Promise<any>;
        };
    };
    utils: {
        mask: {
            create: ({ mask, credentialSubject, holderPublicKey }: import("./types/utils").MaskProps) => {
                maskedClaims: {};
                maskedMasks: {};
            };
            full: ({ mask, credentialSubject, holderPublicKey }: import("./types/utils").MaskProps) => import("./types/utils").Claims;
        };
        signature: {
            key: {
                generate: ({ data, privateKey }: import("./types/utils").GenerateSignatureProps) => string;
                verify: ({ data, signature, publicKey }: import("./types/utils").VerifySignatureProps) => any;
            };
            ethr: {
                generate: ({ data, privateKey }: import("./types/utils").GenerateSignatureProps) => string;
                verify: ({ data, signature, publicKey }: import("./types/utils").VerifySignatureProps) => true;
            };
        };
        ed25519: typeof import("./utils/ed25519").default;
        secp256k1: typeof import("secp256k1");
    };
    functions: typeof functions;
};
export { verifiable, utils, functions };
export default VCSD;
