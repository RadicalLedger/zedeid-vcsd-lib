export interface Claims {
    [key: string]: string;
}
export interface Mask {
    [key: string]: boolean;
}
export interface VC {
    context?: string;
    issuer: {
        did: string;
        publicKey: string;
    };
    subject: {
        did: string;
        publicKey: string;
    };
    type: string;
    claims: Claims;
    proof: string;
    iat?: string;
    exp?: string;
    mask?: Mask;
}
export interface VP {
    context?: string;
    subject: {
        did: string;
        publicKey: string;
    };
    type: string;
    credentials: Array<VC>;
    proof: string;
}
