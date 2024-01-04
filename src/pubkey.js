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

/**
 * @classdesc PubKey is a wrapper for both ECDSA and ECDH crypto.subtle keys.
 *
 * It is capable of export/import operations to/from base64, hex, spki, jwk,
 * raw, coordinates. Additionally it can be imported from PrivKey.
 *
 * crypto.js allows to verify and encrypt with it.
 */
class PubKey {
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
   * @constructor
   * @public
   * @param {CryptoKey} ecdh Generated ECDH public key (extractable).
   * @param {CryptoKey} ecdsa Generated ECDSA public key (extractable).
   */
  constructor (ecdh, ecdsa) {
    this._ecdh = ecdh
    this._ecdsa = ecdsa
  }

  /**
   * @public
   * @description Obtain underlying crypto.subtle ECDH public key for
   * cryptography operations.
   * @returns {CryptoKey} ECDH crypto.subtle public key.
   */
  ecdh () {
    return this._ecdh
  }

  /**
   * @public
   * @description Obtain underlying crypto.subtle ECDSA public key for
   * cryptography operations.
   * @returns {CryptoKey} ECDSA crypto.subtle public key.
   */
  ecdsa () {
    return this._ecdsa
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PubKey from ArrayBuffer in SPKI format.
   * @param {ArrayBuffer} pubBuf ArrayBuffer in SPKI format.
   * @returns {PubKey} Imported PubKey.
   */
  static async fromSpki (pubBuf) {
    const ecdh = await crypto.subtle.importKey(
      'spki',
      pubBuf,
      this.ecdhAlgo,
      true,
      []
    )
    const ecdsa = await crypto.subtle.importKey(
      'spki',
      pubBuf,
      this.ecdsaAlgo,
      true,
      ['verify']
    )
    return new PubKey(ecdh, ecdsa)
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PubKey from base64 string in SPKI format.
   * @param {string} b64 base64 encoded string of SPKI.
   * @returns {PubKey} Imported PubKey.
   */
  static async fromBase64 (b64) {
    const spki = Convert.base64ToArrayBuffer(b64)
    return this.fromSpki(spki)
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PubKey from hex string.
   * @param {string} hex Hex encoded string of SPKI.
   * @returns {PubKey} Imported PubKey.
   */
  static async fromHex (hex) {
    return this.fromSpki(Convert.hexStringToArrayBuffer(hex))
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PubKey from JWK.
   * @param {Object} jwk Object in JWK format.
   * @returns {PubKey} Imported PubKey.
   */
  static async fromJwk (jwk) {
    delete jwk.d
    jwk.key_ops = []
    const ecdh = await crypto.subtle.importKey(
      'jwk',
      jwk,
      this.ecdhAlgo,
      true,
      []
    )
    jwk.key_ops = ['verify']
    const ecdsa = await crypto.subtle.importKey(
      'jwk',
      jwk,
      this.ecdsaAlgo,
      true,
      ['verify']
    )
    return new PubKey(ecdh, ecdsa)
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PubKey from raw.
   * @param {ArrayBuffer} raw Raw representation of a public key.
   * @returns {PubKey} Imported PubKey.
   */
  static async fromRaw (raw) {
    const ecdh = await crypto.subtle.importKey(
      'raw',
      raw,
      this.ecdhAlgo,
      true,
      []
    )
    const ecdsa = await crypto.subtle.importKey(
      'raw',
      raw,
      this.ecdsaAlgo,
      true,
      ['verify']
    )
    return new PubKey(ecdh, ecdsa)
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PubKey from Coordinates.
   * @param {ArrayBuffer} x ArrayBuffer with BigEndian representation of x
   * coordinate.
   * @param {ArrayBuffer} y ArrayBuffer with BigEndian representation of y
   * coordinate.
   * @returns {PubKey} Imported PubKey.
   */
  static async fromCoordinates (x, y) {
    const raw = new Uint8Array(1 + x.byteLength + y.byteLength)
    raw[0] = 0x04
    raw.set(new Uint8Array(x), 1)
    raw.set(new Uint8Array(y), 1 + x.byteLength)
    return this.fromRaw(raw.buffer)
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PubKey from PrivKey.
   * @param {PrivKey} priv Private key to derive from.
   * @returns {PubKey} Imported PubKey.
   */
  static async fromPrivKey (priv) {
    return PubKey.fromJwk(await priv.toJwk())
  }

  /**
   * @public
   * @async
   * @description Export PubKey to RAW format.
   * @returns {ArrayBuffer} Export result.
   */
  async toRaw () {
    return crypto.subtle.exportKey(
      'raw',
      this.ecdh()
    )
  }

  /**
   * @public
   * @async
   * @description Export PubKey to coordinates.
   * @returns {Object} Export result.
   */
  async toCoordinates () {
    const raw = await this.toRaw()
    return {
      x: raw.slice(1, 33),
      y: raw.slice(33, 65)
    }
  }

  /**
   * @public
   * @async
   * @description Export PubKey to SPKI format.
   * @returns {ArrayBuffer} Export result.
   */
  async toSpki () {
    return crypto.subtle.exportKey(
      'spki',
      this.ecdh()
    )
  }

  /**
   * @public
   * @async
   * @description Export PubKey to Base64 encoded string.
   * @returns {string} Export result.
   */
  async toBase64 () {
    const spki = await this.toSpki()
    return Convert.arrayBufferToBase64(spki)
  }

  /**
   * @public
   * @async
   * @description Export PubKey to hex encoded string.
   * @returns {string} Export result.
   */
  async toHex () {
    const spki = await this.toSpki()
    return Convert.arrayBufferToHexString(spki)
  }

  /**
   * @public
   * @async
   * @description Export PubKey to JWK.
   * @returns {Object} Export result.
   */
  async toJwk () {
    return crypto.subtle.exportKey(
      'jwk',
      this.ecdh()
    )
  }
}

export {
  PubKey
}
