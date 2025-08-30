import ed25519 from './ed25519';
import * as secp256k1 from 'secp256k1';
declare const _default: {
    mask: {
        create: ({ mask, credentialSubject, holderPublicKey }: import("../types/utils").MaskProps) => {
            maskedClaims: {};
            maskedMasks: {};
        };
        full: ({ mask, credentialSubject, holderPublicKey }: import("../types/utils").MaskProps) => import("../types/utils").Claims;
    };
    signature: {
        key: {
            generate: ({ data, privateKey }: import("../types/utils").GenerateSignatureProps) => string;
            verify: ({ data, signature, publicKey }: import("../types/utils").VerifySignatureProps) => any;
        };
        ethr: {
            generate: ({ data, privateKey }: import("../types/utils").GenerateSignatureProps) => string;
            verify: ({ data, signature, publicKey }: import("../types/utils").VerifySignatureProps) => true;
        };
    };
    ed25519: typeof ed25519;
    secp256k1: typeof secp256k1;
};
export default _default;
