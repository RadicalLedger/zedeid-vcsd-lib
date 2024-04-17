import { Claims, MaskProps } from '../types/utils.type';
declare const _default: {
    create: ({ mask, credentialSubject, holderPublicKey }: MaskProps) => {
        maskedClaims: {};
        maskedMasks: {};
    };
    full: ({ mask, credentialSubject, holderPublicKey }: MaskProps) => Claims;
};
export default _default;
