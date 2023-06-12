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

/**
 * @classdesc Convert provides two way conversion primitives for base64,
 * urlBase64, hex string and ArrayBuffer.
 */
class Convert {
  /**
   * @public
   * @static
   * @description Convert base64 to urlBase64.
   * @param {string} str base64 encoded string.
   * @returns {string} urlBase64 encoded string.
   */
  static base64ToUrlBase64 (str) {
    return str
      .replaceAll('/', '_')
      .replaceAll('+', '-')
      .replace('=', '')
  }

  /**
   * @public
   * @static
   * @description Convert urlBase64 to base64.
   * @param {string} str urlBase64 encoded string.
   * @returns {string} base64 encoded string.
   */
  static urlBase64ToBase64 (str) {
    return str
      .replaceAll('_', '/')
      .replaceAll('-', '+')
  }

  /**
   * @public
   * @static
   * @description Restore ArrayBuffer from base64 encoded string.
   * @param {string} b64 base64 encoded string.
   * @returns {ArrayBuffer} ArrayBuffer of decoded data.
   */
  static base64ToArrayBuffer (b64) {
    const binaryString = atob(b64)
    const len = binaryString.length
    const array = new Uint8Array(len)
    for (let i = 0; i < len; i++) { array[i] = binaryString.charCodeAt(i) }
    return array.buffer
  }

  /**
   * @public
   * @static
   * @description Convert ArrayBuffer to base64 string.
   * @param {ArrayBuffer} array ArrayBuffer of data.
   * @returns {string} String with base64 encoded contents of the array.
   */
  static arrayBufferToBase64 (array) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(array)))
  }

  /**
   * @public
   * @static
   * @description Convert ArrayBuffer to urlBase64 string.
   * @param {ArrayBuffer} array ArrayBuffer of data.
   * @returns {string} String with urlBase64 encoded contents of the array.
   */
  static arrayBufferToUrlBase64 (array) {
    return this.base64ToUrlBase64(this.arrayBufferToBase64(array))
  }

  /**
   * @public
   * @static
   * @description Restore ArrayBuffer from base64 encoded string.
   * @param {string} ub64 urlBase64 encoded string.
   * @returns {ArrayBuffer} ArrayBuffer of decoded data.
   */
  static urlBase64ToArrayBuffer (ub64) {
    return this.base64ToArrayBuffer(this.urlBase64ToBase64(ub64))
  }

  /**
   * @public
   * @static
   * @description Restore ArrayBuffer from hex string.
   * @param {string} hex Hex encoded string.
   * @returns {ArrayBuffer} ArrayBuffer of decoded data.
   */
  static hexStringToArrayBuffer (hex) {
    return Uint8Array.from(
      hex.split(/(?=(?:..)*$)/),
      n => Number.parseInt(n, 16)
    ).buffer
  }

  /**
   * @public
   * @static
   * @description Convert ArrayBuffer to hex string.
   * @param {ArrayBuffer} buf ArrayBuffer to be converted.
   * @returns {string} Hex string with encoded data.
   */
  static arrayBufferToHexString (buf) {
    return (new Uint8Array(buf)).reduce(
      (s, i) => s + i.toString(16).padStart(2, '0'),
      ''
    )
  }
}

export {
  Convert
}
