import { VerifiableCredential } from '@transmute/vc.js/dist/types/VerifiableCredential';
import { CreateProps, VerifyProps } from '../types/credential';
declare const _default: {
    create: ({ issuerPrivateKey, issuanceDate, documentLoader, credential, suite, didMethod }: CreateProps) => Promise<VerifiableCredential>;
    verify: ({ suite, vc, documentLoader, issuerPublicKey, holderPublicKey, didMethod }: VerifyProps) => Promise<{
        verified: any;
    }>;
};
export default _default;
