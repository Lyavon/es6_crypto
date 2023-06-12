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

/**
 * @classdesc PubKey is a wrapper for both ECDSA and ECDH crypto.subtle keys.
 * It is capable of exporting itself into base64, hex, spki, jwk and can
 * be imported from base64, hex, spki, jwk, coordinates. crypto.js allows to
 * verify and encrypt with it.
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
   * @private
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
   * @private
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
   * @private
   * @async
   * @static
   * @description Import PubKey from base64 string in SPKI format.
   * @param {string} b64 base64 encoded string of SPKI.
   * @returns {PubKey} Imported PubKey.
   */
  static async fromBase64 (b64) {
    return this.fromSpki(Convert.base64ToArrayBuffer(b64))
  }

  /**
   * @private
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
   * @private
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
    const jwk = {
      crv: 'P-256',
      ext: true,
      kty: 'EC',
      x: Convert.arrayBufferToUrlBase64(x),
      y: Convert.arrayBufferToUrlBase64(y)
    }
    return this.fromJwk(jwk)
  }

  /**
   * @private
   * @async
   * @static
   * @description Import PubKey from hex string.
   * @param {string} hex Hex encoded string of SPKI.
   * @returns {PubKey} Imported PubKey.
   */
  static async fromHexString (hex) {
    return this.fromSpki(Convert.hexStringToArrayBuffer(hex))
  }

  /**
   * @public
   * @async
   * @static
   * @description Import PubKey from a given format.
   * @param {string} type Type of source to import from (one of: 'b64', 'hex',
   * 'spki', 'jwk', 'coordinates').
   * @param {...*} args Required arguments for the import.
   * @returns {PubKey} Imported PubKey.
   */
  static async from (type, ...args) {
    switch (type) {
      case 'b64':
        return this.fromBase64(...args)
      case 'hex':
        return this.fromHexString(...args)
      case 'spki':
        return this.fromSpki(...args)
      case 'jwk':
        return this.fromJwk(...args)
      case 'coordinates':
        return this.fromCoordinates(...args)
      default:
        throw new Error(`Unknown type ${type} is provided`)
    }
  }

  /**
   * @public
   * @async
   * @description Export PubKey in a given format.
   * @param {string} [type='b64'] Type of source to import from (one of: 'b64', 'hex',
   * 'spki', 'jwk', 'raw').
   * @returns {*} Export result.
   */
  async export (type = 'b64') {
    switch (type) {
      case 'b64':
        return Convert.arrayBufferToBase64(await this.export('spki'))
      case 'hex':
        return Convert.arrayBufferToHexString(await this.export('spki'))
      default:
        return crypto.subtle.exportKey(
          type,
          this.ecdh()
        )
    }
  }
}

export {
  PubKey
}
