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
  PrivKey
} from './privkey.js'
import {
  PubKey
} from './pubkey.js'

/**
 * @classdesc KeyPair is a container for PrivKey and PubKey. It is capable of
 * exporting itself into base64, hex, pksc8, jwk, raw and can
 * be imported from base64, hex, pkcs8, jwk, d, seed, random. crypto.js allows
 * to sign, verify, encrypt and decrypt with it.
 */
class KeyPair {
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
   * @private
   * @async
   * @static
   * @description Faster way to Import KeyPair from JWK.
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
   * @description Import KeyPair from a given format.
   * @param {string} type Type of source to import from (one of: 'b64', 'hex',
   * 'pkcs8', 'jwk', 'd', 'seed', 'random').
   * @param {...*} args Required arguments for the import.
   * @returns {KeyPair} Imported KeyPair.
   */
  static async from (type, ...args) {
    let priv
    switch (type) {
      case 'b64':
      case 'd':
      case 'hex':
      case 'pkcs8':
      case 'seed':
      case 'random':
        priv = await PrivKey.from(type, ...args)
        return new KeyPair(
          priv,
          await priv.derivePublicKey()
        )
      case 'jwk':
        return this.fromJwk(...args)
      default:
        throw new Error(`Can't create KeyPair from unknown type ${type}`)
    }
  }

  /**
   * @public
   * @async
   * @description Export KeyPair in a given format.
   * @param {string} [type='b64'] Type of source to export to (one of: 'b64',
   * 'hex', 'pkcs8', 'jwk', 'raw').
   * @returns {*} Export result.
   */
  async export (...args) {
    return this.priv().export(...args)
  }
};

export {
  KeyPair
}
