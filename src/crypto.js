/* Copyright 2023, 2024 Leonid Ragunovich
 *
 * This file is part of es6_crypto.
 *
 * es6_crypto is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program (see LICENSE file in parent directory). If not, see
 * <https://www.gnu.org/licenses/>.
 */

import {
  Convert
} from './convert.js'
import {
  KeyPair
} from './keypair.js'
import {
  PrivKey
} from './privkey.js'
import {
  PubKey
} from './pubkey.js'

/**
 * @classdesc Crypto class provides sign, verify, encrypt, decrypt
 * cryptographic operations for KeyPair, PrivKey and PubKey.
 */
class Crypto {
  /**
   * @public
   * @static
   * @async
   * @description Encrypt given data with derived secret key of Alice and Bob.
   * @param {PrivKey|KeyPair} alicePriv PrivKey or KeyPair of a person doing encryption.
   * @param {PubKey|KeyPair} bobPriv PubKey of a person for whom the encryption is
   * happening.
   * @param {ArrayBuffer} dataArray Data to be encrypted.
   * @param {ArrayBuffer} [iv=null] Initial vector for encryption. Will be
   * generated randomly if not provided.
   * @returns {Object} Object containing iv and encryptedData.
   */
  static async encrypt (alicePriv, bobPub, dataArray, iv = null) {
    if (alicePriv instanceof KeyPair) { alicePriv = alicePriv.priv() }
    if (bobPub instanceof KeyPair) { bobPub = bobPub.pub() }
    if (!iv) {
      iv = new Uint8Array(16)
      crypto.getRandomValues(iv)
    }
    const secretKey = await crypto.subtle.deriveKey(
      {
        name: 'ECDH',
        public: bobPub.ecdh()
      },
      alicePriv.ecdh(),
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      [
        'encrypt'
      ]
    )
    return {
      iv,
      encryptedData: await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv
        },
        secretKey,
        dataArray
      )
    }
  }

  /**
   * @static
   * @public
   * @async
   * @description Verify signature.
   * @param {PubKey|KeyPair} PubKey or KeyPair of a person who has signed the
   * data.
   * @param {ArrayBuffer} dataArray ArrayBuffer of data that has been signed.
   * @param {ArrayBuffer} signatureArray ArrayBuffer containing signature.
   * @returns {bool} Boolean verification result.
   */
  static async verify (pub, dataArray, signatureArray) {
    if (pub instanceof KeyPair) { pub = pub.pub() }
    return crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: 'SHA-256'
      },
      pub.ecdsa(),
      signatureArray,
      dataArray
    )
  }

  /**
   * @static
   * @public
   * @async
   * @description Sign data.
   * @param {PrivKey|KeyPair} PrivKey or KeyPair to sign.
   * @param {ArrayBuffer} dataArray ArrayBuffer of data to be signed.
   * @returns {ArrayBuffer} ArrayBuffer that contains signature.
   */
  static async sign (priv, dataArray) {
    if (priv instanceof KeyPair) { priv = priv.priv() }
    return crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: 'SHA-256'
      },
      priv.ecdsa(),
      dataArray
    )
  }

  /**
   * @static
   * @public
   * @async
   * @description Decrypt the data with derived secret of Alice and Bob.
   * @param {PubKey|KeyPair} PubKey alicePub of a person who has done the encryption.
   * @param {PrivKey|KeyPair} bobPriv PrivKey or KeyPair of a person for whom
   * the encryption is done.
   * @param {ArrayBuffer} dataArray ArrayBuffer with encrypted data.
   * @param {ArrayBuffer} iv Initial vector used for encryption.
   * @returns {ArrayBuffer} Decryption result.
   */
  static async decrypt (alicePub, bobPriv, dataArray, iv) {
    if (bobPriv instanceof KeyPair) { bobPriv = bobPriv.priv() }
    if (alicePub instanceof KeyPair) { alicePub = alicePub.pub() }
    const secretKey = await crypto.subtle.deriveKey(
      {
        name: 'ECDH',
        public: alicePub.ecdh()
      },
      bobPriv.ecdh(),
      {
        name: 'AES-GCM',
        length: 256
      },
      false,
      [
        'decrypt'
      ]
    )
    return crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv
      },
      secretKey,
      dataArray
    )
  }
}

export {
  Convert,
  Crypto,
  KeyPair,
  PrivKey,
  PubKey
}
