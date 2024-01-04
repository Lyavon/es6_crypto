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

const KeyPair = crypto.KeyPair
const Crypto = crypto.Crypto

let aliceKp = null
let bobKp = null
const data = (new TextEncoder()).encode('test_data').buffer

beforeEach(async () => {
  aliceKp = await KeyPair.fromRandom()
  bobKp = await KeyPair.fromRandom()
})

test(
  'Crypto can use KeyPair to sign and verify',
  async () => {
    const signature = await Crypto.sign(aliceKp, data)
    expect(await Crypto.verify(aliceKp, data, signature)).toBeTruthy()
  }
)

test(
  'Crypto can use PrivKey and PubKey to sign and verify',
  async () => {
    const signature = await Crypto.sign(aliceKp.priv(), data)
    expect(await Crypto.verify(aliceKp.pub(), data, signature)).toBeTruthy()
  }
)

test(
  'Crypto can use KeyPairs to encrypt and decrypt',
  async () => {
    const encryptedData = await Crypto.encrypt(aliceKp, bobKp.pub(), data)
    const decryptedData = await Crypto.decrypt(
      aliceKp.pub(),
      bobKp,
      encryptedData.encryptedData,
      encryptedData.iv
    )
    expect(decryptedData).toEqual(data)
  }
)

test(
  'Crypto can use PrivKeys to encrypt and decrypt',
  async () => {
    const encryptedData = await Crypto.encrypt(aliceKp.priv(), bobKp.pub(), data)
    const decryptedData = await Crypto.decrypt(
      aliceKp.pub(),
      bobKp.priv(),
      encryptedData.encryptedData,
      encryptedData.iv
    )
    expect(decryptedData).toEqual(data)
  }
)
