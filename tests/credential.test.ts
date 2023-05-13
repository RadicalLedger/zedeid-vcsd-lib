import { verifiable } from '../dist';
import documentLoader from './assets/document-loader';

const issuer = 'did:key:example-1';
const issuerPrivateKey = 'issuer-private-key';
const issuerPublicKey = 'issuer-public-key';

const holder = 'did:key:example-2';
const holderPrivateKey = 'holder-private-key';
const holderPublicKey = 'holder-public-key';

test('Create verifiable credential', async () => {
    const credential = {
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

    const result = await verifiable.credential.create({
        credential,
        holderPublicKey,
        issuerPrivateKey,
        issuanceDate: credential?.issuanceDate || new Date().toISOString(),
        documentLoader
    });

    expect(result).not.toBeNull;
}, 60000); // timeout - 1 minute

test('Verify a verifiable credential', async () => {
    const credential = {
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

    /* create vc */
    const vc = await verifiable.credential.create({
        credential,
        holderPublicKey,
        issuerPrivateKey,
        issuanceDate: credential?.issuanceDate || new Date().toISOString(),
        documentLoader
    });

    /* verify vc */
    const result = await verifiable.credential.verify({
        vc,
        holderPublicKey,
        issuerPublicKey,
        documentLoader
    });

    expect(result?.verified).toBe(true);
}, 60000); // timeout - 1 minute
