# es6\_crypto
es6\_crypto is an convenient wrapper around crypto.subtle. It's aim is to
simplify usage of secp256r1 cryptography for ES6.

## Features:
- Export PubKey to base64, hex, spki, jwk, raw.
- Import PubKey from base64, hex, spki, jwk, coordinates.
- Export PrivKey to base64, hex, pkcs8, jwk.
- Import PrivKey from base64, hex, pkcs8, jwk, d, seed, random.
- Derive PubKey from PrivKey.
- Export and Import KeyPair from and to any Format PrivKey Supports.
- Encrypt, Verify Operations for Single PubKey Instance.
- Decrypt, Sign Operations for Single PrivKey Instance.
- Encrypt, Decrypt, Sign, Verify Operations for Single KeyPair Instance.
- Scripts for Documentation and Linting.

## Dependencies:
- Tom Wu's JSBN library (necessary part is contained in src/tom\_wu)
- jsdoc (optional)
- standard (optional)

## Usage:

### As NPM Package

#### Installation

```sh
# No Dependencies
npm install "git+https://github.com/Lyavon/es6_crypto.git"

# With Dev Dependencies
npm install "git+https://github.com/Lyavon/es6_crypto.git" --save-dev
```

#### Scripts usage
Awailable only if dev dependencies were installed:

```sh
# Generate jsdoc (output is going to *documentation* directory of project root):
npm run documentation

# After generating documentation it can be opened with:
npm run show-documentation

# Run standard (tom_wu directory is untouched):
npm run standard
```

### As Standalone Package

#### Installation

```sh
git clone https://github.com/Lyavon/es6_crypto.git

# Optionally jsdoc and standard may be installed via package manager
```

#### Scripts usage
Awailable only if dev dependencies were installed:

```sh
# Generate documentation (output is going to *documentation* directory of project root):
./scripts/documentation.sh

# After generating documentation it can be opened with:
./scripts/show-documentation.sh

# Run standard (tom_wu directory is untouched):
./scripts/standard.sh
```

### Usage Examples

#### Import and Export PrivKey

```js
// In Browser:
import {
  PrivKey
} from './src/crypto.js'

// In Node:
import {
  PrivKey
} from '@lyavon/es6_crypto'

const privKey1 = await PrivKey.from('random')

const b64 = await privKey1.export('b64')
const privKey2 = await PrivKey.from('b64', b64)

const hex = await privKey2.export('hex')
const privKey3 = await PrivKey.from('hex', hex)

const pkcs8 = await privKey3.export('pkcs8')
const privKey4 = await PrivKey.from('pkcs8', pkcs8)

const jwk = await privKey4.export('jwk')
const privKey5 = await PrivKey.from('jwk', jwk)

const seed = new Uint8Array(32)
crypto.getRandomValues(seed)
const privKey6 = await PrivKey.from('seed', seed)
```

#### Import and Export PubKey

```js
// In Browser:
import {
  Convert,
  PrivKey,
  PubKey
} from './src/crypto.js'

// In Node:
import {
  Convert,
  PrivKey,
  PubKey
} from '@lyavon/es6_crypto'

const privKey = await PrivKey.from('random')
const pubKey1 = await privKey.derivePublicKey()

const b64 = await pubKey1.export('b64')
const pubKey2 = await PubKey.from('b64', b64)

const hex = await pubKey2.export('hex')
const pubKey3 = await PubKey.from('hex', hex)

const spki = await pubKey3.export('spki')
const pubKey4 = await PubKey.from('spki', spki)

const jwk = await pubKey4.export('jwk')
const pubKey5 = await PubKey.from('jwk', jwk)

const x = Convert.urlBase64ToArrayBuffer(jwk.x)
const y = Convert.urlBase64ToArrayBuffer(jwk.y)
const pubKey6 = await PubKey.from('coordinates', x, y)
```

#### Import and Export KeyPair

```js
// In Browser:
import {
  KeyPair
} from './src/crypto.js'

// In Node:
import {
  KeyPair
} from '@lyavon/es6_crypto'

const keyPair1 = await KeyPair.from('random')

const b64 = await keyPair1.export('b64')
const keyPair2 = await KeyPair.from('b64', b64)

const hex = await keyPair2.export('hex')
const keyPair3 = await KeyPair.from('hex', hex)

const pkcs8 = await keyPair3.export('pkcs8')
const keyPair4 = await KeyPair.from('pkcs8', pkcs8)

const jwk = await keyPair4.export('jwk')
const keyPair5 = await KeyPair.from('jwk', jwk)

const seed = new Uint8Array(32)
crypto.getRandomValues(seed)
const keyPair6 = await KeyPair.from('seed', seed)
```

#### Cryptographic operations

```js
// In Browser:
import {
  Convert,
  Crypto,
  KeyPair,
  PrivKey,
  PubKey
} from './src/crypto.js';

// In Node:
import {
  Convert,
  Crypto,
  KeyPair,
  PrivKey,
  PubKey
} from '@lyavon/es6_crypto'

const data = (new TextEncoder()).encode('Test')
const keyPair = await KeyPair.from('random')
const privKey = keyPair.priv()
const pubKey = keyPair.pub()

const sign1 = await Crypto.sign(privKey, data)
const sign2 = await Crypto.sign(keyPair, data)
const ver1 = await Crypto.verify(pubKey, data, sign2)
const ver2 = await Crypto.verify(keyPair, data, sign1)

const iv = new Uint8Array(16)
crypto.getRandomValues(iv)
const tmpKeyPair = await KeyPair.from('random')

const enc1 = await Crypto.encrypt(privKey, tmpKeyPair.pub(), data, iv)
const enc2 = await Crypto.encrypt(keyPair, tmpKeyPair.pub(), data, iv)
const dec1 = await Crypto.decrypt(pubKey, tmpKeyPair.priv(), enc2.encryptedData, enc2.iv)
const dec2 = await Crypto.decrypt(keyPair.pub(), tmpKeyPair, enc1.encryptedData, enc1.iv)
```

## License
This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program (see LICENSE file in this directory). If not, see
<https://www.gnu.org/licenses/>.
