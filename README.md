# es6\_crypto
es6\_crypto is an convenient wrapper around crypto.subtle. Its aim is to
simplify usage of secp256r1 cryptography for ES6.

There are corresponding [java\_crypto](https://github.com/Lyavon/java_crypto)
and [swift\_crypto](https://github.com/Lyavon/swift_crypto) wrappers that
implement crypto.subtle standart and have identical API to this package.

## Features:
- Export PubKey to base64, hex, spki, jwk, raw, coordinates.
- Import PubKey from base64, hex, spki, jwk, raw, coordinates, PrivKey.
- Export PrivKey to base64, hex, pkcs8, jwk, d, raw.
- Import PrivKey from base64, hex, pkcs8, jwk, d, raw seed, random.
- Derive PubKey from PrivKey (see __Import PubKey__).
- Export and Import KeyPair from and to any Format PrivKey Supports.
- Optimized import operations for KeyPair.
- Encrypt, Verify Operations for Single PubKey Instance.
- Decrypt, Sign Operations for Single PrivKey Instance.
- Encrypt, Decrypt, Sign, Verify Operations for Single KeyPair Instance.
- Full compatibility with java\_crypto and swift\_crypto.
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

# Development
git clone https://github.com/Lyavon/es6_crypto.git
cd es6_crypto
npm install
```

#### Scripts usage
Awailable Only for Development:

```sh
# Generate jsdoc (output is going to *documentation* directory of project root):
npm run documentation

# After generating documentation it can be opened with:
npm run show-documentation

# Run standard (tom_wu directory is untouched):
npm run standard

# Run unit tests:
npm run test
```

### As Standalone Package

#### Installation

```sh
git clone https://github.com/Lyavon/es6_crypto.git

# Optionally:
# jsdoc and standard may be installed via package manager or npm
sudo npm install -g jest jsdoc standard
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

# Run unit tests:
./scripts/test.sh
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

const privKey1 = await PrivKey.fromRandom()

const b64 = await privKey1.toBase64()
const privKey2 = await PrivKey.fromBase64(b64)

const hex = await privKey2.toHex()
const privKey3 = await PrivKey.fromHex(hex)

const pkcs8 = await privKey3.toPkcs8()
const privKey4 = await PrivKey.fromPkcs8(pkcs8)

const jwk = await privKey4.toJwk()
const privKey5 = await PrivKey.fromJwk(jwk)

const d = await privKey5.toD()
const privKey6 = await PrivKey.fromD(d)

const raw = await privKey6.toRaw()
const privKey7 = await PrivKey.fromRaw(raw)

const seed = new Uint8Array(32)
crypto.getRandomValues(seed)
const privKey8 = await PrivKey.fromSeed(seed)
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

const privKey = await PrivKey.fromRandom()
const pubKey1 = await PubKey.fromPrivKey(privKey)

const b64 = await pubKey1.toBase64()
const pubKey2 = await PubKey.fromBase64(b64)

const hex = await pubKey2.toHex()
const pubKey3 = await PubKey.fromHex(hex)

const spki = await pubKey3.toSpki()
const pubKey4 = await PubKey.fromSpki(spki)

const jwk = await pubKey4.toJwk()
const pubKey5 = await PubKey.fromJwk(jwk)

const coords = await pubKey5.toCoordinates()
const pubKey6 = await PubKey.fromCoordinates(coords.x, coords.y)

const raw = await pubKey6.toRaw()
const pubKey7 = await PubKey.fromRaw(raw)
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

const keyPair1 = await KeyPair.fromRandom()

const b64 = await keyPair1.toBase64()
const keyPair2 = await KeyPair.fromBase64(b64)

const hex = await keyPair2.toHex()
const keyPair3 = await KeyPair.fromHex(hex)

const pkcs8 = await keyPair3.toPkcs8()
const keyPair4 = await KeyPair.fromPkcs8(pkcs8)

const jwk = await keyPair4.toJwk()
const keyPair5 = await KeyPair.fromJwk(jwk)

const d = await keyPair5.toD()
const keyPair6 = await KeyPair.fromD(d)

const raw = await keyPair6.toRaw()
const keyPair7 = await KeyPair.fromRaw(raw)

const seed = new Uint8Array(32)
crypto.getRandomValues(seed)
const keyPair8 = await KeyPair.fromSeed(seed)
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
} from './src/crypto.js'

// In Node:
import {
  Convert,
  Crypto,
  KeyPair,
  PrivKey,
  PubKey
} from '@lyavon/es6_crypto'

const data = (new TextEncoder()).encode('Test')
const keyPair = await KeyPair.fromRandom()
const privKey = keyPair.priv()
const pubKey = keyPair.pub()

const sign1 = await Crypto.sign(privKey, data)
const sign2 = await Crypto.sign(keyPair, data)
const ver1 = await Crypto.verify(pubKey, data, sign2)
const ver2 = await Crypto.verify(keyPair, data, sign1)

const iv = new Uint8Array(16)
crypto.getRandomValues(iv)
const tmpKeyPair = await KeyPair.fromRandom()

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
