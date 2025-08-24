import { verifiable } from '../../src';
import documentLoader from '../assets/document-loader/loader';

// const issuer = 'did:ethr:0x8f970ca9ddb1ff4848701ccd5a356f310fbd1e8d';
const issuerPrivateKey = '07d146d2a825f4ce3172f545e5417829a20925a245009fab7d265e6c8d204c60';
const issuerPublicKey = '0282f73aed54ebb7830cbf22358cd46e5a358c2a73614e00b8a084dc2683cf75e5';

// const holder = 'did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327';
const holderPrivateKey = 'b5378aebb7ab0d771016c04d1661109d1a7facc464a5a369d7c89abdbaf5a883';
const holderPublicKey = '024c5e565786d4130f20585ed3347fa09c94aeae3ce44ada5d251daadc6bab7f10';

const timeout = 60000; // 1 minute

describe('(ETHR) Create and verify verifiable presentation', () => {
    it(
        'Create verifiable presentation',
        async () => {
            const credential_1 = {
                '@context': [
                    'https://www.w3.org/2018/credentials/v1',
                    'https://cdn.zedeid.com/credentials/microrewards/v2.00/education'
                ],
                id: 'http://localhost:8080/verify/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/8da736d605af5b0591d45c1e2f09264073fe5d3e9b77c1389e6097c247664a42',
                issuanceDate: '2023-04-14T00:00:00Z',
                type: ['VerifiableCredential'],
                issuer: 'did:ethr:0x8f970ca9ddb1ff4848701ccd5a356f310fbd1e8d',
                credentialSubject: {
                    type: ['EducationalAchievementBadge'],
                    holder: 'did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327',
                    title: 'Badge Title',
                    description: 'Successfully Completing the of Marketing Diploma',
                    issuerLogo: 'https://picsum.photos/500/500',
                    issuerName: 'Sample Organization',
                    issuerUrl: 'http://localhost:8080/issuer-profile/1',
                    holderImage: 'https://picsum.photos/300/300',
                    holderName: 'John Stark',
                    holderProfileUrl:
                        'http://localhost:8080/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/rewards',
                    remarks: 'Sample remark about this badge',
                    visualPresentation: 'https://picsum.photos/500/500',
                    customAttribute: []
                }
            };

            const credential_2 = {
                '@context': [
                    'https://www.w3.org/2018/credentials/v1',
                    'https://cdn.zedeid.com/credentials/microrewards/v2.00/education'
                ],
                id: 'http://localhost:3002/verify/did:ethr:0x0Ff956599b1d6307aAa5B5076B856Bd93fd6b235/febacf38ee473284ef4276f380dbfe5e113b21fffc960c361b91ed6037d7bd09',
                issuanceDate: '2023-02-23T00:00:00Z',
                type: ['VerifiableCredential'],
                issuer: 'did:ethr:0x8f970ca9ddb1ff4848701ccd5a356f310fbd1e8d',
                credentialSubject: {
                    type: ['EducationalAchievementTranscript'],
                    achievementInfo: {
                        type: ['EducationalAchievementCertificate'],
                        holder: 'did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327',
                        title: 'Transcript Title',
                        description: 'Successfully Completing the of Marketing Diploma',
                        issuerLogo: 'https://picsum.photos/500/500',
                        issuerName: 'Sample Organization',
                        issuerUrl: 'http://localhost:8080/issuer-profile/1',
                        holderImage: 'https://picsum.photos/300/300',
                        holderName: 'John Stark',
                        holderProfileUrl:
                            'http://localhost:8080/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/rewards',
                        conductedBy: 'Mr. Stark',
                        signature: ['https://picsum.photos/500/200'],
                        remarks: 'Sample remark about this transcript',
                        visualPresentation: 'https://picsum.photos/500/500'
                    },
                    subject: [],
                    customAttribute: []
                }
            };

            const verifiableCredential = await Promise.all([
                verifiable.credential.create({
                    credential: credential_1,
                    holderPublicKey,
                    issuerPrivateKey,
                    issuanceDate: credential_1?.issuanceDate || new Date().toISOString(),
                    documentLoader
                }),
                verifiable.credential.create({
                    credential: credential_2,
                    holderPublicKey,
                    issuerPrivateKey,
                    issuanceDate: credential_2?.issuanceDate || new Date().toISOString(),
                    documentLoader
                })
            ]);

            const result = await verifiable.presentation.create({
                documentLoader: documentLoader,
                holderPrivateKey,
                verifiableCredential
            });

            expect(result).not.toBeNull;
        },
        timeout
    );

    it(
        'Create a masked verifiable presentation',
        async () => {
            const credential_1 = {
                '@context': [
                    'https://www.w3.org/2018/credentials/v1',
                    'https://cdn.zedeid.com/credentials/microrewards/v2.00/education'
                ],
                id: 'http://localhost:8080/verify/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/8da736d605af5b0591d45c1e2f09264073fe5d3e9b77c1389e6097c247664a42',
                issuanceDate: '2023-04-14T00:00:00Z',
                type: ['VerifiableCredential'],
                issuer: 'did:ethr:0x8f970ca9ddb1ff4848701ccd5a356f310fbd1e8d',
                credentialSubject: {
                    type: ['EducationalAchievementBadge'],
                    holder: 'did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327',
                    title: 'Badge Title',
                    description: 'Successfully Completing the of Marketing Diploma',
                    issuerLogo: 'https://picsum.photos/500/500',
                    issuerName: 'Sample Organization',
                    issuerUrl: 'http://localhost:8080/issuer-profile/1',
                    holderImage: 'https://picsum.photos/300/300',
                    holderName: 'John Stark',
                    holderProfileUrl:
                        'http://localhost:8080/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/rewards',
                    remarks: 'Sample remark about this badge',
                    visualPresentation: 'https://picsum.photos/500/500',
                    customAttribute: []
                }
            };

            const credential_2 = {
                '@context': [
                    'https://www.w3.org/2018/credentials/v1',
                    'https://cdn.zedeid.com/credentials/microrewards/v2.00/education'
                ],
                id: 'http://localhost:3002/verify/did:ethr:0x0Ff956599b1d6307aAa5B5076B856Bd93fd6b235/febacf38ee473284ef4276f380dbfe5e113b21fffc960c361b91ed6037d7bd09',
                issuanceDate: '2023-02-23T00:00:00Z',
                type: ['VerifiableCredential'],
                issuer: 'did:ethr:0x8f970ca9ddb1ff4848701ccd5a356f310fbd1e8d',
                credentialSubject: {
                    type: ['EducationalAchievementTranscript'],
                    achievementInfo: {
                        type: ['EducationalAchievementCertificate'],
                        holder: 'did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327',
                        title: 'Transcript Title',
                        description: 'Successfully Completing the of Marketing Diploma',
                        issuerLogo: 'https://picsum.photos/500/500',
                        issuerName: 'Sample Organization',
                        issuerUrl: 'http://localhost:8080/issuer-profile/1',
                        holderImage: 'https://picsum.photos/300/300',
                        holderName: 'John Stark',
                        holderProfileUrl:
                            'http://localhost:8080/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/rewards',
                        conductedBy: 'Mr. Stark',
                        signature: ['https://picsum.photos/500/200'],
                        remarks: 'Sample remark about this transcript',
                        visualPresentation: 'https://picsum.photos/500/500'
                    },
                    subject: [],
                    customAttribute: []
                }
            };

            const verifiableCredential = await Promise.all([
                verifiable.credential.create({
                    credential: credential_1,
                    holderPublicKey,
                    issuerPrivateKey,
                    issuanceDate: credential_1?.issuanceDate || new Date().toISOString(),
                    documentLoader
                }),
                verifiable.credential.create({
                    credential: credential_2,
                    holderPublicKey,
                    issuerPrivateKey,
                    issuanceDate: credential_2?.issuanceDate || new Date().toISOString(),
                    documentLoader
                })
            ]);

            const result = await verifiable.presentation.create({
                documentLoader: documentLoader,
                holderPrivateKey,
                verifiableCredential,
                masks: [{ title: true, holderImage: true }, { achievementInfo: { remarks: true } }]
            });

            expect(result).not.toBeNull;
        },
        timeout
    );

    it.only(
        'Verify a verifiable presentation',
        async () => {
            const credential_1 = {
                '@context': [
                    'https://www.w3.org/2018/credentials/v1',
                    'https://cdn.zedeid.com/credentials/microrewards/v2.00/education'
                ],
                id: 'http://localhost:8080/verify/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/8da736d605af5b0591d45c1e2f09264073fe5d3e9b77c1389e6097c247664a42',
                issuanceDate: '2023-04-14T00:00:00Z',
                type: ['VerifiableCredential'],
                issuer: 'did:ethr:0x8f970ca9ddb1ff4848701ccd5a356f310fbd1e8d',
                credentialSubject: {
                    type: ['EducationalAchievementBadge'],
                    holder: 'did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327',
                    title: 'Badge Title',
                    description: 'Successfully Completing the of Marketing Diploma',
                    issuerLogo: 'https://picsum.photos/500/500',
                    issuerName: 'Sample Organization',
                    issuerUrl: 'http://localhost:8080/issuer-profile/1',
                    holderImage: 'https://picsum.photos/300/300',
                    holderName: 'John Stark',
                    holderProfileUrl:
                        'http://localhost:8080/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/rewards',
                    remarks: 'Sample remark about this badge',
                    visualPresentation: 'https://picsum.photos/500/500',
                    customAttribute: []
                }
            };

            const credential_2 = {
                '@context': [
                    'https://www.w3.org/2018/credentials/v1',
                    'https://cdn.zedeid.com/credentials/microrewards/v2.00/education'
                ],
                id: 'http://localhost:3002/verify/did:ethr:0x0Ff956599b1d6307aAa5B5076B856Bd93fd6b235/febacf38ee473284ef4276f380dbfe5e113b21fffc960c361b91ed6037d7bd09',
                issuanceDate: '2023-02-23T00:00:00Z',
                type: ['VerifiableCredential'],
                issuer: 'did:ethr:0x8f970ca9ddb1ff4848701ccd5a356f310fbd1e8d',
                credentialSubject: {
                    type: ['EducationalAchievementTranscript'],
                    achievementInfo: {
                        type: ['EducationalAchievementCertificate'],
                        holder: 'did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327',
                        title: 'Transcript Title',
                        description: 'Successfully Completing the of Marketing Diploma',
                        issuerLogo: 'https://picsum.photos/500/500',
                        issuerName: 'Sample Organization',
                        issuerUrl: 'http://localhost:8080/issuer-profile/1',
                        holderImage: 'https://picsum.photos/300/300',
                        holderName: 'John Stark',
                        holderProfileUrl:
                            'http://localhost:8080/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/rewards',
                        conductedBy: 'Mr. Stark',
                        signature: ['https://picsum.photos/500/200'],
                        remarks: 'Sample remark about this transcript',
                        visualPresentation: 'https://picsum.photos/500/500'
                    },
                    subject: [],
                    customAttribute: []
                }
            };

            const verifiableCredential = await Promise.all([
                verifiable.credential.create({
                    credential: credential_1,
                    holderPublicKey,
                    issuerPrivateKey,
                    issuanceDate: credential_1?.issuanceDate || new Date().toISOString(),
                    documentLoader
                }),
                verifiable.credential.create({
                    credential: credential_2,
                    holderPublicKey,
                    issuerPrivateKey,
                    issuanceDate: credential_2?.issuanceDate || new Date().toISOString(),
                    documentLoader
                })
            ]);

            const vp = await verifiable.presentation.create({
                documentLoader,
                holderPrivateKey,
                verifiableCredential
            });

            const result = await verifiable.presentation.verify({
                vp,
                issuerPublicKey,
                holderPublicKey,
                documentLoader
            });

            expect(result?.verified).toBe(true);
        },
        timeout
    );

    it(
        'Verify a verifiable presentation without issuer and holder public keys',
        async () => {
            const credential_1 = {
                '@context': [
                    'https://www.w3.org/2018/credentials/v1',
                    'https://cdn.zedeid.com/credentials/microrewards/v2.00/education'
                ],
                id: 'http://localhost:8080/verify/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/8da736d605af5b0591d45c1e2f09264073fe5d3e9b77c1389e6097c247664a42',
                issuanceDate: '2023-04-14T00:00:00Z',
                type: ['VerifiableCredential'],
                issuer: 'did:ethr:0x8f970ca9ddb1ff4848701ccd5a356f310fbd1e8d',
                credentialSubject: {
                    type: ['EducationalAchievementBadge'],
                    holder: 'did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327',
                    title: 'Badge Title',
                    description: 'Successfully Completing the of Marketing Diploma',
                    issuerLogo: 'https://picsum.photos/500/500',
                    issuerName: 'Sample Organization',
                    issuerUrl: 'http://localhost:8080/issuer-profile/1',
                    holderImage: 'https://picsum.photos/300/300',
                    holderName: 'John Stark',
                    holderProfileUrl:
                        'http://localhost:8080/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/rewards',
                    remarks: 'Sample remark about this badge',
                    visualPresentation: 'https://picsum.photos/500/500',
                    customAttribute: []
                }
            };

            const credential_2 = {
                '@context': [
                    'https://www.w3.org/2018/credentials/v1',
                    'https://cdn.zedeid.com/credentials/microrewards/v2.00/education'
                ],
                id: 'http://localhost:3002/verify/did:ethr:0x0Ff956599b1d6307aAa5B5076B856Bd93fd6b235/febacf38ee473284ef4276f380dbfe5e113b21fffc960c361b91ed6037d7bd09',
                issuanceDate: '2023-02-23T00:00:00Z',
                type: ['VerifiableCredential'],
                issuer: 'did:ethr:0x8f970ca9ddb1ff4848701ccd5a356f310fbd1e8d',
                credentialSubject: {
                    type: ['EducationalAchievementTranscript'],
                    achievementInfo: {
                        type: ['EducationalAchievementCertificate'],
                        holder: 'did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327',
                        title: 'Transcript Title',
                        description: 'Successfully Completing the of Marketing Diploma',
                        issuerLogo: 'https://picsum.photos/500/500',
                        issuerName: 'Sample Organization',
                        issuerUrl: 'http://localhost:8080/issuer-profile/1',
                        holderImage: 'https://picsum.photos/300/300',
                        holderName: 'John Stark',
                        holderProfileUrl:
                            'http://localhost:8080/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/rewards',
                        conductedBy: 'Mr. Stark',
                        signature: ['https://picsum.photos/500/200'],
                        remarks: 'Sample remark about this transcript',
                        visualPresentation: 'https://picsum.photos/500/500'
                    },
                    subject: [],
                    customAttribute: []
                }
            };

            const verifiableCredential = await Promise.all([
                verifiable.credential.create({
                    credential: credential_1,
                    issuerPrivateKey,
                    issuanceDate: credential_1?.issuanceDate || new Date().toISOString(),
                    documentLoader
                }),
                verifiable.credential.create({
                    credential: credential_2,
                    issuerPrivateKey,
                    holderPublicKey,
                    issuanceDate: credential_2?.issuanceDate || new Date().toISOString(),
                    documentLoader
                })
            ]);

            const vp = await verifiable.presentation.create({
                documentLoader,
                holderPrivateKey,
                verifiableCredential
            });

            const result = await verifiable.presentation.verify({
                vp,
                documentLoader
            });

            expect(result?.verified).toBe(true);
        },
        timeout
    );

    it(
        'Verify a masked verifiable presentation without issuer and holder public keys',
        async () => {
            const credential_1 = {
                '@context': [
                    'https://www.w3.org/2018/credentials/v1',
                    'https://cdn.zedeid.com/credentials/microrewards/v2.00/education'
                ],
                id: 'http://localhost:8080/verify/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/8da736d605af5b0591d45c1e2f09264073fe5d3e9b77c1389e6097c247664a42',
                issuanceDate: '2023-04-14T00:00:00Z',
                type: ['VerifiableCredential'],
                issuer: 'did:ethr:0x8f970ca9ddb1ff4848701ccd5a356f310fbd1e8d',
                credentialSubject: {
                    type: ['EducationalAchievementBadge'],
                    holder: 'did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327',
                    title: 'Badge Title',
                    description: 'Successfully Completing the of Marketing Diploma',
                    issuerLogo: 'https://picsum.photos/500/500',
                    issuerName: 'Sample Organization',
                    issuerUrl: 'http://localhost:8080/issuer-profile/1',
                    holderImage: 'https://picsum.photos/300/300',
                    holderName: 'John Stark',
                    holderProfileUrl:
                        'http://localhost:8080/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/rewards',
                    remarks: 'Sample remark about this badge',
                    visualPresentation: 'https://picsum.photos/500/500',
                    customAttribute: []
                }
            };

            const credential_2 = {
                '@context': [
                    'https://www.w3.org/2018/credentials/v1',
                    'https://cdn.zedeid.com/credentials/microrewards/v2.00/education'
                ],
                id: 'http://localhost:3002/verify/did:ethr:0x0Ff956599b1d6307aAa5B5076B856Bd93fd6b235/febacf38ee473284ef4276f380dbfe5e113b21fffc960c361b91ed6037d7bd09',
                issuanceDate: '2023-02-23T00:00:00Z',
                type: ['VerifiableCredential'],
                issuer: 'did:ethr:0x8f970ca9ddb1ff4848701ccd5a356f310fbd1e8d',
                credentialSubject: {
                    type: ['EducationalAchievementTranscript'],
                    achievementInfo: {
                        type: ['EducationalAchievementCertificate'],
                        holder: 'did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327',
                        title: 'Transcript Title',
                        description: 'Successfully Completing the of Marketing Diploma',
                        issuerLogo: 'https://picsum.photos/500/500',
                        issuerName: 'Sample Organization',
                        issuerUrl: 'http://localhost:8080/issuer-profile/1',
                        holderImage: 'https://picsum.photos/300/300',
                        holderName: 'John Stark',
                        holderProfileUrl:
                            'http://localhost:8080/did:ethr:0x5ccd4ae58c4ab2785dc14e358f9b0ae543048327/rewards',
                        conductedBy: 'Mr. Stark',
                        signature: ['https://picsum.photos/500/200'],
                        remarks: 'Sample remark about this transcript',
                        visualPresentation: 'https://picsum.photos/500/500'
                    },
                    subject: [],
                    customAttribute: []
                }
            };

            const verifiableCredential = await Promise.all([
                verifiable.credential.create({
                    credential: credential_1,
                    issuerPrivateKey,
                    issuanceDate: credential_1?.issuanceDate || new Date().toISOString(),
                    documentLoader
                }),
                verifiable.credential.create({
                    credential: credential_2,
                    issuerPrivateKey,
                    issuanceDate: credential_2?.issuanceDate || new Date().toISOString(),
                    documentLoader
                })
            ]);

            const vp = await verifiable.presentation.create({
                documentLoader,
                holderPrivateKey,
                verifiableCredential,
                masks: [{ title: true, holderImage: true }]
            });

            const result = await verifiable.presentation.verify({
                vp,
                documentLoader
            });

            expect(result?.verified).toBe(true);
        },
        timeout
    );
});
