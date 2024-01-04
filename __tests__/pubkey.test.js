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

const crypto = await import('../src/crypto.js')

const Convert = crypto.Convert
const PubKey = crypto.PubKey
const KeyPair = crypto.KeyPair

let kp = null

beforeEach(async () => {
  kp = await KeyPair.fromRandom()
})

test(
  'PubKey can be exported and imported back as base64',
  async () => {
    const pub = kp.pub()
    const b64 = await pub.toBase64()
    expect(await PubKey.fromBase64(b64)).toEqual(pub)
  }
)

test(
  'PubKey can be exported and imported back as hex',
  async () => {
    const pub = kp.pub()
    const hex = await pub.toHex()
    expect(await PubKey.fromHex(hex)).toEqual(pub)
  }
)

test(
  'PubKey can be exported and imported back as jwk',
  async () => {
    const pub = kp.pub()
    const jwk = await pub.toJwk()
    expect(await PubKey.fromJwk(jwk)).toEqual(pub)
  }
)

test(
  'PubKey can be exported and imported back as spki',
  async () => {
    const pub = kp.pub()
    const spki = await pub.toSpki()
    expect(await PubKey.fromSpki(spki)).toEqual(pub)
  }
)

test(
  'PubKey can be exported and imported back as raw',
  async () => {
    const pub = kp.pub()
    const raw = await pub.toRaw()
    expect(await PubKey.fromRaw(raw)).toEqual(pub)
  }
)

test(
  'PubKey can be exported and imported back as coordinates',
  async () => {
    const pub = kp.pub()
    const coordinates = await pub.toCoordinates()
    expect(await PubKey.fromCoordinates(coordinates.x, coordinates.y)).toEqual(pub)
  }
)

test(
  'PubKey can be imported from PrivKey',
  async () => {
    expect(await PubKey.fromPrivKey(kp.priv())).toEqual(kp.pub())
  }
)
