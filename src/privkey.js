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
  BigInteger
} from './tom_vu/BigInteger.js'
import {
  ECCurveFp
} from './tom_vu/ec.js'

/**
 * @description PrivKey needs to perform software public key derivation.
 * Therefore, BigInreger needs to be carried around with PrivKey.
 * @external BigInteger
 */

/**
 * @description PrivKey needs to perform software public key derivation.
 * Therefore, ECCurveFp needs to be carried around with PrivKey.
 * @external ECCurveFp
 */

/**
 * @classdesc PrivKey is a wrapper for both ECDSA and ECDH crypto.subtle keys,
 * which is convenient for conversions and merging ECDH and ECDSA together.
 *
 * PrivKey is capable of the following:
 * - Import and export to/from pkcs8, base64, hex, jwk, raw, d.
 * - Import from seed, random.
 *
 * crypto.js allows to sign and decrypt with it.
 */
class PrivKey {
  /**
   * @private
   * @static
   * @description Predefined algorithm for ECDH.
   */
  static ecdhAlgo = {
    name: 'ECDH',
    namedCurve: 'P-256'
  }

  /**
   * @private
   * @static
   * @description Predefined algorithm for ECDSA.
   */
  static ecdsaAlgo = {
    name: 'ECDSA',
    namedCurve: 'P-256'
  }

  /**
   * @private
   * @static
   * @description Predefined G point for public key derivation.
   */
  static G = new ECCurveFp(
    new BigInteger(
      'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF',
      16
    ),
    new BigInteger(
      'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC',
      16
    ),
    new BigInteger(
      '5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B',
      16
    )
  ).decodePointHex(
    '046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296' +
    '4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5'
  )

  /**
   * @constructor
   * @public
   * @param {CryptoKey} ecdh Generated ECDH private key (extractable).
   * @param {CryptoKey} ecdsa Generated ECDSA private key (extractable).
   */
  constructor (ecdh, ecdsa) {
    this._ecdh = ecdh
    this._ecdsa = ecdsa
  }

  /**
   * @public
   * @description Obtain underlying crypto.subtle ECDH private key for
   * cryptography operations.
   * @returns {CryptoKey} ECDH crypto.subtle private key.
   */
  ecdh () {
    return this._ecdh
  }

  /**
   * @public
   * @description Obtain underlying crypto.subtle ECDSA private key for
   * cryptography operations.
   * @returns {CryptoKey} ECDSA crypto.subtle private key.
   */
  ecdsa () {
    return this._ecdsa
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PrivKey from ArrayBuffer in PKCS8 format.
   * @param {ArrayBuffer} buf ArrayBuffer in PKCS8 format.
   * @returns {PrivKey} Imported PrivKey.
   */
  static async fromPkcs8 (buf) {
    const ecdh = await crypto.subtle.importKey(
      'pkcs8',
      buf,
      this.ecdhAlgo,
      true,
      ['deriveKey']
    )
    const ecdsa = await crypto.subtle.importKey(
      'pkcs8',
      buf,
      this.ecdsaAlgo,
      true,
      ['sign']
    )
    return new PrivKey(ecdh, ecdsa)
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PrivKey from base64 in PKCS8 format.
   * @param {string} b64 Base64 encoded string of PKCS8.
   * @returns {PrivKey} Imported PrivKey.
   */
  static async fromBase64 (b64) {
    return this.fromPkcs8(Convert.base64ToArrayBuffer(b64))
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PrivKey from hex string in PKCS8 format.
   * @param {string} hex Encoded string of PKCS8.
   * @returns {PrivKey} Imported PrivKey.
   */
  static async fromHex (hex) {
    return this.fromPkcs8(Convert.hexStringToArrayBuffer(hex))
  }

  static pkcs8DHeader = new Uint8Array([
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30,
    0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04,
    0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04,
    0x20
  ])

  static pkcs8XYHeader = new Uint8Array([
    0xa1, 0x44, 0x03, 0x42, 0x00, 0x04
  ])

  /**
   * @public
   * @async
   * @static
   * @description Import PrivKey from RAW.
   * @param {ArrayBuffer} raw PrivKey exported to RAW.
   * @returns {PrivKey} Imported PrivKey.
   */
  static async fromRaw (raw) {
    const rawArray = new Uint8Array(raw)
    const pkcs8 = new Uint8Array(
      this.pkcs8DHeader.length + this.pkcs8XYHeader.length + 96
    )
    pkcs8.set(this.pkcs8DHeader, 0)
    pkcs8.set(rawArray.subarray(65, 97), 36)
    pkcs8.set(this.pkcs8XYHeader, 68)
    pkcs8.set(rawArray.subarray(1, 65), 74)
    return PrivKey.fromPkcs8(pkcs8)
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PrivKey from JWK.
   * @param {Object} jwk Object representing JWK.
   * @returns {PrivKey} Imported PrivKey.
   */
  static async fromJwk (jwk) {
    jwk.key_ops = ['deriveKey']
    const ecdh = await crypto.subtle.importKey(
      'jwk',
      jwk,
      this.ecdhAlgo,
      true,
      ['deriveKey']
    )
    jwk.key_ops = ['sign']
    const ecdsa = await crypto.subtle.importKey(
      'jwk',
      jwk,
      this.ecdsaAlgo,
      true,
      ['sign']
    )
    return new PrivKey(ecdh, ecdsa)
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PrivKey from d value.
   * @param {ArrayBuffer} dBuf ArrayBuffer with d value in BigEndian.
   * @returns {PrivKey} Imported PrivKey.
   */
  static async fromD (dBuf) {
    const bigIntD = new BigInteger(
      Convert.arrayBufferToHexString(dBuf),
      16
    )
    const p = this.G.multiply(bigIntD)
    const bigIntX = p.getX().toBigInteger()
    const rawX = Convert.hexStringToArrayBuffer(bigIntX.toString(16))
    const bigIntY = p.getY().toBigInteger()
    const rawY = Convert.hexStringToArrayBuffer(bigIntY.toString(16))
    const pkcs8 = new Uint8Array(
      this.pkcs8DHeader.length + this.pkcs8XYHeader.length + 96
    )
    pkcs8.set(this.pkcs8DHeader, 0)
    pkcs8.set(new Uint8Array(dBuf), 36)
    pkcs8.set(this.pkcs8XYHeader, 68)
    pkcs8.set(new Uint8Array(rawX), 74)
    pkcs8.set(new Uint8Array(rawY), 106)
    return this.fromPkcs8(pkcs8.buffer)
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PrivKey from a seed. Seed is an initial value for
   * PrivKey generation. Consecutive hashing is applied to it until it becomes
   * valid d value.
   * @param {ArrayBuffer} seed ArrayBuffer with initial (seed) value.
   * @returns {PrivKey} Imported PrivKey.
   */
  static async fromSeed (seed) {
    try {
      const key = await this.fromD(seed)
      return key
    } catch (e) {
      return this.fromSeed(
        await crypto.subtle.digest('SHA-256', seed)
      )
    }
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PrivKey from random.
   * @returns {PrivKey} Imported PrivKey.
   */
  static async fromRandom () {
    const pair = await crypto.subtle.generateKey(
      this.ecdhAlgo,
      true,
      ['deriveKey']
    )
    const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
    return this.fromJwk(jwk)
  }

  /**
   * @public
   * @async
   * @description Export PrivKey to JWK.
   * @returns {Object} Exported PrivKey to JWK.
   */
  async toJwk () {
    return crypto.subtle.exportKey('jwk', this.ecdh())
  }

  /**
   * @public
   * @async
   * @description Export PrivKey to PKCS8.
   * @returns {ArrayBuffer} Exported PrivKey to PKCS8.
   */
  async toPkcs8 () {
    return crypto.subtle.exportKey('pkcs8', this.ecdh())
  }

  /**
   * @public
   * @async
   * @description Export PrivKey to Hex.
   * @returns {string} Exported PrivKey to Hex.
   */
  async toHex () {
    const pkcs8 = await this.toPkcs8()
    return Convert.arrayBufferToHexString(pkcs8)
  }

  /**
   * @public
   * @async
   * @description Export PrivKey to Hex.
   * @returns {string} Exported PrivKey to Hex.
   */
  async toBase64 () {
    const pkcs8 = await this.toPkcs8()
    return Convert.arrayBufferToBase64(pkcs8)
  }

  /**
   * @public
   * @async
   * @description Export PrivKey to D.
   * @returns {ArrayBuffer} Exported PrivKey.
   */
  async toD () {
    const d = (await this.toJwk()).d
    return Convert.urlBase64ToArrayBuffer(d)
  }

  /**
   * @public
   * @async
   * @description Export PrivKey to RAW.
   * @returns {ArrayBuffer} Exported PrivKey.
   */
  async toRaw () {
    const pkcs8 = new Uint8Array(await this.toPkcs8())
    const raw = new Uint8Array(97)
    raw[0] = 0x04
    raw.set(pkcs8.subarray(74, 138), 1)
    raw.set(pkcs8.subarray(36, 68), 65)
    return raw.buffer
  }
}

export {
  PrivKey
}
