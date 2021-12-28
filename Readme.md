# sd-vc-lib

Package for issue, present and verify selectively disclossable verifiable credentials.

Also available via: https://cdn.jsdelivr.net/npm/@zedeid-sdk/sd-vc-lib/dist/browser/zedeid-vcsd.js

## Breaking changes

Credentials and presentations issued with v1.0.0 will no longer be valid with v2.0.0

## Usage

### issue

import { issue } from 'sd-vc-lib';

Issue selectively disclosable credentials for given claims.

#### Parameters

1. signerPrivateKey | issuer: string | Signer - hex-encoded private key(Ethereum) | signer object for issuer
2. claims: Claims - list of key-value pairs.
3. holderPublicKey: string - hex-encoded public key(Ethereum)

#### Returns

1. VC - signed selectively disclosable verifiable credential.

### present

import { present } from 'sd-vc-lib';

Present given list of verifiable credentials.

#### Parameters

1. holderPrivateKey | holder: string | Signer - hex encoded private key(Ethereum) | signer object for holder
2. credentials: VC[] - list of verifiable credentials.
3. masks: Mask[] - list of masks.

#### Returns

1. VP - presentation of a set of selectively disclosed verifiable credentials.

### verify

import { verify } from 'sd-vc-lib';

verify the authenticity of a verifiable presentation.

#### Parameters

1. vp: VP - valid mnemonic phrase.
2. signerPublicKeys: string[] - set of hex-encoded public keys(Ethereum)
3. holderPublicKey: string - hex-encoded public key(Ethereum)

#### Returns

1. boolean - true if valid.

### verifyVC

import { verifyVC } from 'sd-vc-lib';

verify the authenticity of a verifiable credential.

#### Parameters

1. vc: VC - verifiable credential.
2. signerPublicKey: string - hex-encoded public key(Ethereum).
3. holderPublicKey: string - hex-encoded public key(Ethereum).

#### Returns

1. boolean - true if a verifiable credential is valid.