import { GenerateSignatureProps, VerifySignatureProps } from '../types/utils.type';
declare const _default: {
    key: {
        generate: ({ data, privateKey }: GenerateSignatureProps) => string;
        verify: ({ data, signature, publicKey }: VerifySignatureProps) => any;
    };
    ethr: {
        generate: ({ data, privateKey }: GenerateSignatureProps) => string;
        verify: ({ data, signature, publicKey }: VerifySignatureProps) => true;
    };
    moon: {
        generate: ({ data, privateKey }: GenerateSignatureProps) => string;
        verify: ({ data, signature, publicKey }: VerifySignatureProps) => true;
    };
};
export default _default;
