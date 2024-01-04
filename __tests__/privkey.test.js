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
const PrivKey = crypto.PrivKey

let priv = null

beforeEach(async () => {
  priv = await PrivKey.fromRandom()
})

test(
  'PrivKey can be exported and imported back as base64',
  async () => {
    const b64 = await priv.toBase64()
    expect(await PrivKey.fromBase64(b64)).toEqual(priv)
  }
)

test(
  'PrivKey can be exported and imported back as hex',
  async () => {
    const hex = await priv.toHex()
    expect(await PrivKey.fromHex(hex)).toEqual(priv)
  }
)

test(
  'PrivKey can be exported and imported back as jwk',
  async () => {
    const jwk = await priv.toJwk()
    expect(await PrivKey.fromJwk(jwk)).toEqual(priv)
  }
)

test(
  'PrivKey can be exported and imported back as pkcs8',
  async () => {
    const pkcs8 = await priv.toPkcs8()
    expect(await PrivKey.fromPkcs8(pkcs8)).toEqual(priv)
  }
)

test(
  'PrivKey can be exported and imported back as d',
  async () => {
    const d = await priv.toD()
    expect(await PrivKey.fromD(d)).toEqual(priv)
  }
)

test(
  'PrivKey can be exported and imported back as raw',
  async () => {
    const raw = await priv.toRaw()
    expect(await PrivKey.fromRaw(raw)).toEqual(priv)
  }
)

test(
  'PrivKey can be imported as seed',
  async () => {
    const password = (new TextEncoder()).encode('my_secret_password')
    const priv1 = await PrivKey.fromSeed(password)
    const priv2 = await PrivKey.fromSeed(password)
    expect(priv1).toEqual(priv2)
  }
)

test(
  'PrivKey can be imported as random',
  async () => {
    expect(
      (await (await PrivKey.fromRandom()).toHex()) ===
      (await priv.toHex())
    ).toBeFalsy()
  }
)
