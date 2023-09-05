import { verifiable } from '../dist';
import documentLoader from './assets/document-loader';

const issuer = 'did:key:z6Mkoqgh9AppS2s28onvE4Qy9jwDBJ8ZqRdBtoWLSsRL57Jj';
const issuerPrivateKey = 'ed710c0f8812e360dafa4dd2888b7ff24d2401223daf961e7e78988a56fa24a4';
const issuerPublicKey = '8b77d43d90cde6652f71387d4a67256bd0fe40a9f78d993a987c1732db178eac';

const holder = 'did:key:z6MksWwdG9DoeDrzrhQrMvj8B9hWG7i6eWomiz9AX6hquCwq';
const holderPrivateKey = 'aa3d9fe749be75c037602f062d34e08f4f163914e41e4042e052d5e2e079d207';
const holderPublicKey = 'c2196d230267c18d101e51cb34d318e375f2100c268f2ffd6e9baef1d905a058';

test('Create verifiable credential', async () => {
    const credential = {
        '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://d202eicx1ap3m7.cloudfront.net/credentials/microrewards/v0-01/microrewards-schema-v0-03.json'
        ],
        id: 'http://localhost:8080/verify/did:key:z6MksWwdG9DoeDrzrhQrMvj8B9hWG7i6eWomiz9AX6hquCwq/8da736d605af5b0591d45c1e2f09264073fe5d3e9b77c1389e6097c247664a42',
        issuanceDate: '2023-04-14T00:00:00Z',
        type: ['VerifiableCredential'],
        issuer: 'did:key:z6Mkoqgh9AppS2s28onvE4Qy9jwDBJ8ZqRdBtoWLSsRL57Jj',
        credentialSubject: {
            type: ['EducationalAchievementBadge'],
            holder: 'did:key:z6MksWwdG9DoeDrzrhQrMvj8B9hWG7i6eWomiz9AX6hquCwq',
            title: 'Badge Title',
            description: 'Successfully Completing the of Marketing Diploma',
            issuerLogo: 'https://picsum.photos/500/500',
            issuerName: 'Sample Organization',
            issuerUrl: 'http://localhost:8080/issuer-profile/1',
            holderImage: 'https://picsum.photos/300/300',
            holderName: 'John Stark',
            holderProfileUrl:
                'http://localhost:8080/did:key:z6MksWwdG9DoeDrzrhQrMvj8B9hWG7i6eWomiz9AX6hquCwq/rewards',
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
            'https://www.w3.org/2018/credentials/v1',
            'https://d202eicx1ap3m7.cloudfront.net/credentials/microrewards/v0-01/microrewards-schema-v0-03.json'
        ],
        id: 'http://localhost:8080/verify/did:key:z6MksWwdG9DoeDrzrhQrMvj8B9hWG7i6eWomiz9AX6hquCwq/8da736d605af5b0591d45c1e2f09264073fe5d3e9b77c1389e6097c247664a42',
        issuanceDate: '2023-04-14T00:00:00Z',
        type: ['VerifiableCredential'],
        issuer: 'did:key:z6Mkoqgh9AppS2s28onvE4Qy9jwDBJ8ZqRdBtoWLSsRL57Jj',
        credentialSubject: {
            type: ['EducationalAchievementBadge'],
            holder: 'did:key:z6MksWwdG9DoeDrzrhQrMvj8B9hWG7i6eWomiz9AX6hquCwq',
            title: 'Badge Title',
            description: 'Successfully Completing the of Marketing Diploma',
            issuerLogo: 'https://picsum.photos/500/500',
            issuerName: 'Sample Organization',
            issuerUrl: 'http://localhost:8080/issuer-profile/1',
            holderImage: 'https://picsum.photos/300/300',
            holderName: 'John Stark',
            holderProfileUrl:
                'http://localhost:8080/did:key:z6MksWwdG9DoeDrzrhQrMvj8B9hWG7i6eWomiz9AX6hquCwq/rewards',
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

test('Verify a verifiable credential without holder public key', async () => {
    const credential = {
        '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://d202eicx1ap3m7.cloudfront.net/credentials/microrewards/v0-01/microrewards-schema-v0-03.json'
        ],
        id: 'http://localhost:8080/verify/did:key:z6MksWwdG9DoeDrzrhQrMvj8B9hWG7i6eWomiz9AX6hquCwq/8da736d605af5b0591d45c1e2f09264073fe5d3e9b77c1389e6097c247664a42',
        issuanceDate: '2023-04-14T00:00:00Z',
        type: ['VerifiableCredential'],
        issuer: 'did:key:z6Mkoqgh9AppS2s28onvE4Qy9jwDBJ8ZqRdBtoWLSsRL57Jj',
        credentialSubject: {
            type: ['EducationalAchievementBadge'],
            holder: 'did:key:z6MksWwdG9DoeDrzrhQrMvj8B9hWG7i6eWomiz9AX6hquCwq',
            title: 'Badge Title',
            description: 'Successfully Completing the of Marketing Diploma',
            issuerLogo: 'https://picsum.photos/500/500',
            issuerName: 'Sample Organization',
            issuerUrl: 'http://localhost:8080/issuer-profile/1',
            holderImage: 'https://picsum.photos/300/300',
            holderName: 'John Stark',
            holderProfileUrl:
                'http://localhost:8080/did:key:z6MksWwdG9DoeDrzrhQrMvj8B9hWG7i6eWomiz9AX6hquCwq/rewards',
            remarks: 'Sample remark about this badge',
            visualPresentation: 'https://picsum.photos/500/500',
            customAttribute: []
        }
    };

    /* create vc */
    const vc = await verifiable.credential.create({
        credential,
        issuerPrivateKey,
        issuanceDate: credential?.issuanceDate || new Date().toISOString(),
        documentLoader
    });

    /* verify vc */
    const result = await verifiable.credential.verify({
        vc,
        documentLoader
    });

    expect(result?.verified).toBe(true);
}, 60000); // timeout - 1 minute
