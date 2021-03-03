# sd-vc-lib

Package for issue, present and verify selectively disclossable verifiable credentials.

## Inastallation

1. Clone repository
2. run *npm run build* 
3. npm install < local repository directory >

## Usage

### issue

import { issue } from 'sd-vc-lib';

Issue selectively disclosable credentials for given claims.

#### Parameters

1. claims : Claims - list of key value pairs.
2. signerPrivateKey : string - hex encoded private key(Ethereum)
3. holderPublicKey : string - hex encoded public key(Ethereum)

#### Returns

1. verifiableCredential: VC - signed selectively disclosable verifiable credential.

### present

import { present } from 'sd-vc-lib';

Present given list of verifiable credentials.

#### Parameters

1. credentials : VC[] - list of verifiable credentials.
2. masks : Mask[] - list of masks.
3. holderPrivateKey : string - hex encoded private key(Ethereum)

#### Returns

1. verifiablePresentation: VP - presentation of set of selectively disclosed verifiable credentials.

### verify

import { verify } from 'sd-vc-lib';

verify authenticity of a verifiable presentaion.

#### Parameters

1. vp : VP - valid mnemonic phrase.
2. signerPublicKeys : string[] - set of hex encoded public keys(Ethereum)
3. holderPublicKey : string - hex encoded public key(Ethereum)

#### Returns

1. verified: Promise< boolean > - resolve to true if valid.

### verifyVC

import { verifyVC } from 'sd-vc-lib';

verify authenticity of a verifiable credential.

#### Parameters

1. vc : VC - verifiable credential.
2. signerPublicKey : string - hex encoded public key(Ethereum).
3. holderPublicKey : string - hex encoded public key(Ethereum).

#### Returns

1. verified: Promise< boolean > - resolve to true if verifiable credential is valid.