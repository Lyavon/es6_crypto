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
const KeyPair = crypto.KeyPair

let kp = null

beforeEach(async () => {
  kp = await KeyPair.from('random')
})

test(
  'KeyPair can be exported and imported back as base64',
  async () => {
    const b64 = await kp.export('b64')
    expect(await KeyPair.from('b64', b64)).toEqual(kp)
  }
)

test(
  'KeyPair can be exported and imported back as hex',
  async () => {
    const hex = await kp.export('hex')
    expect(await KeyPair.from('hex', hex)).toEqual(kp)
  }
)

test(
  'KeyPair can be exported and imported back as jwk',
  async () => {
    const jwk = await kp.export('jwk')
    expect(await KeyPair.from('jwk', jwk)).toEqual(kp)
  }
)

test(
  'KeyPair can be exported and imported back as pkcs8',
  async () => {
    const pkcs8 = await kp.export('pkcs8')
    expect(await KeyPair.from('pkcs8', pkcs8)).toEqual(kp)
  }
)

test(
  'KeyPair can be imported as seed',
  async () => {
    const password = (new TextEncoder()).encode('my_secret_password')
    const kp1 = await KeyPair.from('seed', password)
    const kp2 = await KeyPair.from('seed', password)
    expect(kp1).toEqual(kp2)
  }
)

test(
  'KeyPair can be imported as d',
  async () => {
    const jwk = await kp.export('jwk')
    const d = Convert.urlBase64ToArrayBuffer(jwk.d)
    expect(await KeyPair.from('d', d)).toEqual(kp)
  }
)

test(
  'KeyPair can be imported as random',
  async () => {
    expect(
      (await (await KeyPair.from('random')).export('hex')) ===
      (await kp.export('hex'))
    ).toBeFalsy()
  }
)
