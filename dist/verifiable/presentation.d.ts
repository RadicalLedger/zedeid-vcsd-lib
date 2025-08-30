import { VerifiablePresentation } from '@transmute/vc.js/dist/types/VerifiablePresentation';
import { CreateProps, VerifyProps } from '../types/presentation';
declare const _default: {
    create: ({ suite, challenge, issuanceDate, domain, documentLoader, holderPrivateKey, verifiableCredential, masks, didMethod }: CreateProps) => Promise<VerifiablePresentation>;
    verify: ({ suite, challenge, domain, vp, documentLoader, issuerPublicKey, holderPublicKey, didMethod }: VerifyProps) => Promise<any>;
};
export default _default;
