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

const Crypto = await import('node:crypto')
const crypto = await import('../src/crypto.js')
const Convert = crypto.Convert

const array = new Uint8Array(32)

beforeEach(() => {
  Crypto.getRandomValues(array)
})

test(
  'urlBase64 string for secp256r1 (32 bytes of payload) contains only [a-zA-Z0-9_-]',
  () => {
    const ub64 = Convert.arrayBufferToUrlBase64(array.buffer)
    expect(ub64).toMatch(/[A-Za-z0-9_-]/)
  }
)

test(
  'base64 string for secp256r1 (32 bytes of payload) contains only [a-zA-Z0-9+/=]',
  () => {
    const b64 = Convert.arrayBufferToBase64(array.buffer)
    expect(b64).toMatch(/[A-Za-z0-9+/=]/)
  }
)

test('hex string for secp256r1 (32 bytes of payload) contains only [0-9a-fA-F]',
  () => {
    const hex = Convert.arrayBufferToHexString(array.buffer)
    expect(hex).toMatch(/[A-Fa-f0-9]/)
  }
)

test(
  'ArrayBuffer can be restored after conversion to hex string',
  () => {
    const hex = Convert.arrayBufferToHexString(array.buffer)
    expect(Convert.hexStringToArrayBuffer(hex)).toEqual(array.buffer)
  }
)

test(
  'ArrayBuffer can be restored after conversion to urlBase64',
  () => {
    const ub64 = Convert.arrayBufferToUrlBase64(array.buffer)
    expect(Convert.urlBase64ToArrayBuffer(ub64)).toEqual(array.buffer)
  }
)

test(
  'ArrayBuffer can be restored after conversion to base64',
  () => {
    const b64 = Convert.arrayBufferToBase64(array.buffer)
    expect(Convert.base64ToArrayBuffer(b64)).toEqual(array.buffer)
  }
)

test(
  'ArrayBuffer can be restored after conversion to base64 and then to urlBase64',
  () => {
    const b64 = Convert.arrayBufferToBase64(array.buffer)
    const ub64 = Convert.base64ToUrlBase64(b64)
    expect(Convert.urlBase64ToArrayBuffer(ub64)).toEqual(array.buffer)
  }
)

test(
  'ArrayBuffer can be restored after conversion to urlBase64 and then to base64',
  () => {
    const ub64 = Convert.arrayBufferToUrlBase64(array.buffer)
    const b64 = Convert.urlBase64ToBase64(ub64)
    expect(Convert.base64ToArrayBuffer(b64)).toEqual(array.buffer)
  }
)
