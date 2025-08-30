declare const _default: {
    credential: {
        create: ({ issuerPrivateKey, issuanceDate, documentLoader, credential, suite, didMethod }: import("../types/credential").CreateProps) => Promise<import("@transmute/vc.js/dist/types/VerifiableCredential").VerifiableCredential>;
        verify: ({ suite, vc, documentLoader, issuerPublicKey, holderPublicKey, didMethod }: import("../types/credential").VerifyProps) => Promise<{
            verified: any;
        }>;
    };
    presentation: {
        create: ({ suite, challenge, issuanceDate, domain, documentLoader, holderPrivateKey, verifiableCredential, masks, didMethod }: import("../types/presentation").CreateProps) => Promise<import("@transmute/vc.js/dist/types/VerifiablePresentation").VerifiablePresentation>;
        verify: ({ suite, challenge, domain, vp, documentLoader, issuerPublicKey, holderPublicKey, didMethod }: import("../types/presentation").VerifyProps) => Promise<any>;
    };
};
export default _default;
