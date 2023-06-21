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
const PrivKey = crypto.PrivKey

let priv = null

beforeEach(async () => {
  priv = await PrivKey.from('random')
})

test(
  'PrivKey can be exported and imported back as base64',
  async () => {
    const b64 = await priv.export('b64')
    expect(await PrivKey.from('b64', b64)).toEqual(priv)
  }
)

test(
  'PrivKey can be exported and imported back as hex',
  async () => {
    const hex = await priv.export('hex')
    expect(await PrivKey.from('hex', hex)).toEqual(priv)
  }
)

test(
  'PrivKey can be exported and imported back as jwk',
  async () => {
    const jwk = await priv.export('jwk')
    expect(await PrivKey.from('jwk', jwk)).toEqual(priv)
  }
)

test(
  'PrivKey can be exported and imported back as pkcs8',
  async () => {
    const pkcs8 = await priv.export('pkcs8')
    expect(await PrivKey.from('pkcs8', pkcs8)).toEqual(priv)
  }
)

test(
  'PrivKey can be imported as seed',
  async () => {
    const password = (new TextEncoder()).encode('my_secret_password')
    const priv1 = await PrivKey.from('seed', password)
    const priv2 = await PrivKey.from('seed', password)
    expect(priv1).toEqual(priv2)
  }
)

test(
  'PrivKey can be imported as d',
  async () => {
    const jwk = await priv.export('jwk')
    const d = Convert.urlBase64ToArrayBuffer(jwk.d)
    expect(await PrivKey.from('d', d)).toEqual(priv)
  }
)

test(
  'PrivKey can be imported as random',
  async () => {
    expect(
      (await (await PrivKey.from('random')).export('hex')) ===
      (await priv.export('hex'))
    ).toBeFalsy()
  }
)

test(
  'PrivKey can derive PubKey',
  async () => {
    expect(await priv.derivePublicKey()).toBeDefined()
  }
)
