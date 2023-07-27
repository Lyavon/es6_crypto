/* Copyright 2023 Leonid Ragunovich
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
 * @classdesc PrivKey is a wrapper for both ECDSA and ECDH crypto.subtle keys.
 * It is capable of exporting itself into base64, hex, pksc8, jwk, d and can
 * be imported from base64, hex, pkcs8, jwk, d, seed, random. crypto.js allows
 * to sign and decrypt with it.
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
   * @private
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
   * @private
   * @async
   * @static
   * @description Import PrivKey from ArrayBuffer in PKCS8 format.
   * @param {ArrayBuffer} buf ArrayBuffer in PKCS format.
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
   * @private
   * @async
   * @static
   * @description Import PrivKey from base64 in PKCS8 format.
   * @param {string} b64 base64 encoded string of PKCS8.
   * @returns {PrivKey} Imported PrivKey.
   */
  static async fromBase64 (b64) {
    return this.fromPkcs8(Convert.base64ToArrayBuffer(b64))
  }

  /**
   * @private
   * @async
   * @static
   * @description Import PrivKey from hex string in PKCS8 format.
   * @param {string} hex encoded string of PKCS8.
   * @returns {PrivKey} Imported PrivKey.
   */
  static async fromHexString (hex) {
    return this.fromPkcs8(Convert.hexStringToArrayBuffer(hex))
  }

  /**
   * @private
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
   * @private
   * @async
   * @static
   * @description Import PrivKey from raw d value.
   * @param {ArrayBuffer} dBuf ArrayBuffer with d value in BigEndian.
   * @returns {PrivKey} Imported PrivKey.
   */
  static async fromRawD (dBuf) {
    const bigIntD = new BigInteger(
      Convert.arrayBufferToHexString(dBuf),
      16
    )
    const p = this.G.multiply(bigIntD)
    const bigIntX = p.getX().toBigInteger()
    const rawX = Convert.hexStringToArrayBuffer(bigIntX.toString(16))
    const bigIntY = p.getY().toBigInteger()
    const rawY = Convert.hexStringToArrayBuffer(bigIntY.toString(16))
    const jwk = {
      crv: 'P-256',
      d: Convert.arrayBufferToUrlBase64(dBuf),
      ext: true,
      key_ops: ['deriveKey'],
      kty: 'EC',
      x: Convert.arrayBufferToUrlBase64(rawX),
      y: Convert.arrayBufferToUrlBase64(rawY)
    }
    return this.fromJwk(jwk)
  }

  /**
   * @private
   * @async
   * @static
   * @description Import PrivKey from raw d value.
   * @param {string} d D value as urlBase64 encoded string.
   * @returns {PrivKey} Imported PrivKey.
   */
  static async fromD (d) {
    return this.fromRawD(Convert.urlBase64ToArrayBuffer(d))
  }

  /**
   * @private
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
      const key = await this.fromRawD(seed)
      return key
    } catch (e) {
      return this.fromSeed(
        await crypto.subtle.digest('SHA-256', seed)
      )
    }
  }

  /**
   * @private
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
   * @static
   * @description Import PrivKey from a given format.
   * @param {string} type Type of source to import from (one of: 'b64', 'hex',
   * 'pkcs8', 'jwk', 'd', 'seed', 'random').
   * @param {...*} args Required arguments for the import.
   * @returns {PrivKey} Imported PrivKey.
   */
  static async from (type, ...args) {
    switch (type) {
      case 'b64':
        return this.fromBase64(...args)
      case 'hex':
        return this.fromHexString(...args)
      case 'pkcs8':
        return this.fromPkcs8(...args)
      case 'jwk':
        return this.fromJwk(...args)
      case 'd':
        return this.fromD(...args)
      case 'seed':
        return this.fromSeed(...args)
      case 'random':
        return this.fromRandom(...args)
      default:
        throw new Error(`Can't create Priv key from unknown type ${type}`)
    }
  }

  /**
   * @public
   * @async
   * @description Export PrivKey in a given format.
   * @param {string} [type='b64'] Type of source to export to (one of: 'b64',
   * 'hex', 'pkcs8', 'jwk', 'd').
   * @returns {*} Export result.
   */
  async export (type = 'b64') {
    switch (type) {
      case 'b64':
        return Convert.arrayBufferToBase64(await this.export('pkcs8'))
      case 'hex':
        return Convert.arrayBufferToHexString(await this.export('pkcs8'))
      case 'd':
        return (await this.export('jwk')).d
      default:
        return crypto.subtle.exportKey(type, this.ecdh())
    }
  }
}

export {
  PrivKey
}
