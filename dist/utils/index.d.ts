import ed25519 from './ed25519';
import * as secp256k1 from 'secp256k1';
declare const _default: {
    mask: {
        create: ({ mask, credentialSubject, holderPublicKey }: import("../types/utils.type").MaskProps) => {
            maskedClaims: {};
            maskedMasks: {};
        };
        full: ({ mask, credentialSubject, holderPublicKey }: import("../types/utils.type").MaskProps) => import("../types/utils.type").Claims;
    };
    signature: {
        key: {
            generate: ({ data, privateKey }: import("../types/utils.type").GenerateSignatureProps) => string;
            verify: ({ data, signature, publicKey }: import("../types/utils.type").VerifySignatureProps) => any;
        };
        ethr: {
            generate: ({ data, privateKey }: import("../types/utils.type").GenerateSignatureProps) => string;
            verify: ({ data, signature, publicKey }: import("../types/utils.type").VerifySignatureProps) => true;
        };
        moon: {
            generate: ({ data, privateKey }: import("../types/utils.type").GenerateSignatureProps) => string;
            verify: ({ data, signature, publicKey }: import("../types/utils.type").VerifySignatureProps) => true;
        };
    };
    ed25519: typeof ed25519;
    secp256k1: typeof secp256k1;
};
export default _default;
