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

const crypto = await import('../src/crypto.js')

const Convert = crypto.Convert
const PubKey = crypto.PubKey
const KeyPair = crypto.KeyPair

let kp = null

beforeEach(async () => {
  kp = await KeyPair.from('random')
})

test(
  'PubKey can be exported and imported back as base64',
  async () => {
    const pub = kp.pub()
    const b64 = await pub.export('b64')
    expect(await PubKey.from('b64', b64)).toEqual(pub)
  }
)

test(
  'PubKey can be exported and imported back as hex',
  async () => {
    const pub = kp.pub()
    const hex = await pub.export('hex')
    expect(await PubKey.from('hex', hex)).toEqual(pub)
  }
)

test(
  'PubKey can be exported and imported back as jwk',
  async () => {
    const pub = kp.pub()
    const jwk = await pub.export('jwk')
    expect(await PubKey.from('jwk', jwk)).toEqual(pub)
  }
)

test(
  'PubKey can be exported and imported back as spki',
  async () => {
    const pub = kp.pub()
    const spki = await pub.export('spki')
    expect(await PubKey.from('spki', spki)).toEqual(pub)
  }
)

test(
  'PubKey can be exported as raw',
  async () => {
    const pub = kp.pub()
    expect(await pub.export('raw')).toBeDefined()
  }
)

test(
  'PubKey can be imported as coordinates',
  async () => {
    const pub = kp.pub()
    const jwk = await pub.export('jwk')
    const x = Convert.urlBase64ToArrayBuffer(jwk.x)
    const y = Convert.urlBase64ToArrayBuffer(jwk.y)
    expect(await PubKey.from('coordinates', x, y)).toEqual(pub)
  }
)
