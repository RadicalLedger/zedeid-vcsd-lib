import { verifiable } from '../dist';
import documentLoader from './assets/document-loader';

const issuer = 'did:key:example-1';
const issuerPrivateKey = 'issuer-private-key';
const issuerPublicKey = 'issuer-public-key';

const holder = 'did:key:example-2';
const holderPrivateKey = 'holder-private-key';
const holderPublicKey = 'holder-public-key';

test('Create verifiable presentation', async () => {
    const credential_1 = {
        '@context': [
            'https://www.w3.org/2018/credentials/v1'
        ],
        id: 'http://localhost:8080/1',
        issuanceDate: '2023-04-14T00:00:00Z',
        type: ['VerifiableCredential'],
        issuer: 'did:key:example-1',
        credentialSubject: {
            type: ['EducationalAchievementBadge'],
            holder: 'did:key:example-2',
            title: 'Badge Title',
            description: 'Successfully Completing the of Marketing Diploma',
            issuerLogo: 'https://picsum.photos/500/500',
            issuerName: 'Sample Organization',
            issuerUrl: 'http://localhost:8080/issuer-profile/1',
            holderImage: 'https://picsum.photos/300/300',
            holderName: 'John Stark',
            holderProfileUrl:
                'http://localhost:8080/did:key:example-2/rewards',
            remarks: 'Sample remark about this badge',
            visualPresentation: 'https://picsum.photos/500/500',
            customAttribute: []
        }
    };

    const credential_2 = {
        '@context': [
            'https://www.w3.org/2018/credentials/v1'
        ],
        id: 'http://localhost:3002/2',
        issuanceDate: '2023-02-23T00:00:00Z',
        type: ['VerifiableCredential'],
        issuer: 'did:key:example-1',
        credentialSubject: {
            type: ['EducationalAchievementTranscript'],
            achievementInfo: {
                type: ['EducationalAchievementCertificate'],
                holder: 'did:key:example-2',
                title: 'Transcript Title',
                description: 'Successfully Completing the of Marketing Diploma',
                issuerLogo: 'https://picsum.photos/500/500',
                issuerName: 'Sample Organization',
                issuerUrl: 'http://localhost:8080/issuer-profile/1',
                holderImage: 'https://picsum.photos/300/300',
                holderName: 'John Stark',
                holderProfileUrl:
                    'http://localhost:8080/did:key:example-2/rewards',
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
        documentLoader,
        holderPrivateKey,
        verifiableCredential
    });

    expect(result).not.toBeNull;
}, 60000); // timeout - 1 minute

test('Verify a verifiable presentation', async () => {
    const credential_1 = {
        '@context': [
            'https://www.w3.org/2018/credentials/v1'
        ],
        id: 'http://localhost:8080/1',
        issuanceDate: '2023-04-14T00:00:00Z',
        type: ['VerifiableCredential'],
        issuer: 'did:key:example-1',
        credentialSubject: {
            type: ['EducationalAchievementBadge'],
            holder: 'did:key:example-2',
            title: 'Badge Title',
            description: 'Successfully Completing the of Marketing Diploma',
            issuerLogo: 'https://picsum.photos/500/500',
            issuerName: 'Sample Organization',
            issuerUrl: 'http://localhost:8080/issuer-profile/1',
            holderImage: 'https://picsum.photos/300/300',
            holderName: 'John Stark',
            holderProfileUrl:
                'http://localhost:8080/did:key:example-2/rewards',
            remarks: 'Sample remark about this badge',
            visualPresentation: 'https://picsum.photos/500/500',
            customAttribute: []
        }
    };

    const credential_2 = {
        '@context': [
            'https://www.w3.org/2018/credentials/v1'
        ],
        id: 'http://localhost:3002/2',
        issuanceDate: '2023-02-23T00:00:00Z',
        type: ['VerifiableCredential'],
        issuer: 'did:key:example-1',
        credentialSubject: {
            type: ['EducationalAchievementTranscript'],
            achievementInfo: {
                type: ['EducationalAchievementCertificate'],
                holder: 'did:key:example-2',
                title: 'Transcript Title',
                description: 'Successfully Completing the of Marketing Diploma',
                issuerLogo: 'https://picsum.photos/500/500',
                issuerName: 'Sample Organization',
                issuerUrl: 'http://localhost:8080/issuer-profile/1',
                holderImage: 'https://picsum.photos/300/300',
                holderName: 'John Stark',
                holderProfileUrl:
                    'http://localhost:8080/did:key:example-2/rewards',
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
}, 60000); // timeout - 1 minute
