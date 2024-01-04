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
  PrivKey
} from './privkey.js'
import {
  PubKey
} from './pubkey.js'
import {
  BigInteger
} from './tom_vu/BigInteger.js'

/**
 * @description PrivKey needs to perform software public key derivation.
 * Therefore, BigInreger needs to be carried around with PrivKey.
 * @external BigInteger
 */

/**
 * @classdesc KeyPair is a container for PrivKey and PubKey.
 *
 * It is capable of all the imports and exports that PrivKey is capable of (and
 * has optimizations for simultaneous imports).
 *
 * crypto.js allows to sign, verify, encrypt and decrypt with it.
 */
class KeyPair {
  /**
   * @constructor
   * @public
   * @param {PrivKey} Generated PrivKey.
   * @param {PubKey} PubKey corresponding to the former.
   */
  constructor (priv, pub) {
    this._priv = priv
    this._pub = pub
  }

  /**
   * @public
   * @description Obtain underlying PrivKey.
   * @returns {PrivKey} Underlying PrivKey.
   */
  priv () {
    return this._priv
  }

  /**
   * @public
   * @description Obtain underlying PubKey.
   * @returns {PubKey} Underlying PubKey.
   */
  pub () {
    return this._pub
  }

  /**
   * @public
   * @async
   * @static
   * @description Import KeyPair from JWK.
   * @param {Object} jwk Object representing JWK.
   * @returns {KeyPair} Imported KeyPair.
   */
  static async fromJwk (jwk) {
    return new KeyPair(
      await PrivKey.fromJwk(jwk),
      await PubKey.fromJwk(jwk)
    )
  }

  /**
   * @public
   * @async
   * @static
   * @description Import KeyPair from PKCS8.
   * @param {ArrayBuffer} pkcs8 PKCS8 exported private key.
   * @returns {KeyPair} Imported KeyPair.
   */
  static async fromPkcs8 (pkcs8) {
    const priv = PrivKey.fromPkcs8(pkcs8)
    const rawPub = new Uint8Array(65)
    rawPub[0] = 0x04
    rawPub.set((new Uint8Array(pkcs8)).subarray(74, 138), 1)
    const pub = PubKey.fromRaw(rawPub.buffer)
    return new KeyPair(
      await priv,
      await pub
    )
  }

  /**
   * @public
   * @async
   * @static
   * @description Import KeyPair from Base64.
   * @param {string} b64 Base64 exported private key.
   * @returns {KeyPair} Imported KeyPair.
   */
  static async fromBase64 (b64) {
    const pkcs8 = Convert.base64ToArrayBuffer(b64)
    return KeyPair.fromPkcs8(pkcs8)
  }

  /**
   * @public
   * @async
   * @static
   * @description Import KeyPair from Hex.
   * @param {string} hex Hex exported private key.
   * @returns {KeyPair} Imported KeyPair.
   */
  static async fromHex (hex) {
    const pkcs8 = Convert.hexStringToArrayBuffer(hex)
    return KeyPair.fromPkcs8(pkcs8)
  }

  /**
   * @public
   * @async
   * @static
   * @description Import KeyPair from RAW.
   * @param {ArrayBuffer} raw Raw exported private key.
   * @returns {KeyPair} Imported KeyPair.
   */
  static async fromRaw (raw) {
    const priv = PrivKey.fromRaw(raw)
    const rawPub = (new Uint8Array(raw)).subarray(0, 65)
    const rawPubCopy = new Uint8Array(65)
    rawPubCopy.set(rawPub, 0)
    const pub = PubKey.fromRaw(rawPubCopy.buffer)
    return new KeyPair(
      await priv,
      await pub
    )
  }

  /**
   * @public
   * @async
   * @static
   * @description Import KeyPair from D private part.
   * @param {ArrayBuffer} dBuf D private part.
   * @returns {KeyPair} Imported KeyPair.
   */
  static async fromD (dBuf) {
    const bigIntD = new BigInteger(
      Convert.arrayBufferToHexString(dBuf),
      16
    )
    const p = PrivKey.G.multiply(bigIntD)
    const bigIntX = p.getX().toBigInteger()
    const rawX = Convert.hexStringToArrayBuffer(bigIntX.toString(16))
    const bigIntY = p.getY().toBigInteger()
    const rawY = Convert.hexStringToArrayBuffer(bigIntY.toString(16))
    const rawXArr = new Uint8Array(rawX)
    const rawYArr = new Uint8Array(rawY)

    const pkcs8 = new Uint8Array(
      PrivKey.pkcs8DHeader.length + PrivKey.pkcs8XYHeader.length + 96
    )
    pkcs8.set(PrivKey.pkcs8DHeader, 0)
    pkcs8.set(new Uint8Array(dBuf), 36)
    pkcs8.set(PrivKey.pkcs8XYHeader, 68)
    pkcs8.set(rawXArr, 74)
    pkcs8.set(rawYArr, 106)

    const priv = PrivKey.fromPkcs8(pkcs8.buffer)
    const rawPub = new Uint8Array(65)
    rawPub[0] = 0x04
    rawPub.set(rawXArr, 1)
    rawPub.set(rawYArr, 33)
    const pub = PubKey.fromRaw(rawPub.buffer)
    return new KeyPair(
      await priv,
      await pub
    )
  }

  /**
   * @public
   * @async
   * @static
   * @description Import KeyPair from random.
   * @returns {KeyPair} Imported KeyPair.
   */
  static async fromRandom () {
    const pair = await crypto.subtle.generateKey(
      PrivKey.ecdhAlgo,
      true,
      ['deriveKey']
    )
    const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
    return this.fromJwk(jwk)
  }

  /**
   * @public
   * @async
   * @static
   * @description Import KeyPair from a seed. Seed is an initial value for
   * PrivKey generation. Consecutive hashing is applied to it until it becomes
   * valid d value.
   * @param {ArrayBuffer} seed ArrayBuffer with initial (seed) value.
   * @returns {KeyPair} Imported KeyPair.
   */
  static async fromSeed (seed) {
    try {
      const pair = await this.fromD(seed)
      return pair
    } catch (e) {
      return this.fromSeed(
        await crypto.subtle.digest('SHA-256', seed)
      )
    }
  }

  /**
   * @public
   * @async
   * @description Export KeyPair's private key to PKCS8.
   * @returns {ArrayBuffer} Export result.
   */
  async toPkcs8 () {
    return this.priv().toPkcs8()
  }

  /**
   * @public
   * @async
   * @description Export KeyPair's private key to RAW.
   * @returns {ArrayBuffer} Export result.
   */
  async toRaw () {
    return this.priv().toRaw()
  }

  /**
   * @public
   * @async
   * @description Export KeyPair's private key to D.
   * @returns {ArrayBuffer} Export result.
   */
  async toD () {
    return this.priv().toD()
  }

  /**
   * @public
   * @async
   * @description Export KeyPair's private key to Hex.
   * @returns {string} Export result.
   */
  async toHex () {
    return this.priv().toHex()
  }

  /**
   * @public
   * @async
   * @description Export KeyPair's private key to Base64.
   * @returns {string} Export result.
   */
  async toBase64 () {
    return this.priv().toBase64()
  }

  /**
   * @public
   * @async
   * @description Export KeyPair's private key to JWK.
   * @returns {Object} Export result.
   */
  async toJwk () {
    return this.priv().toJwk()
  }
};

export {
  KeyPair
}
