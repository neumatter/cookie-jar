
import randomBytes from '@neumatter/random-bytes'
import ByteView from 'byteview'

const U32_MASK64 = BigInt(2 ** 32 - 1)
const b32n = BigInt(32)

class U64Array {
  constructor (arrayOfBigInts, isLittleEndian = false) {
    const { length } = arrayOfBigInts
    this.h = new Uint32Array(length)
    this.l = new Uint32Array(length)
    let index = -1

    while (++index < length) {
      if (isLittleEndian) {
        this.h[index] = Number(arrayOfBigInts[index] & U32_MASK64)
        this.l[index] = Number((arrayOfBigInts[index] >> b32n) & U32_MASK64)
      } else {
        this.h[index] = Number((arrayOfBigInts[index] >> b32n) & U32_MASK64) | 0
        this.l[index] = Number(arrayOfBigInts[index] & U32_MASK64) | 0
      }
    }
  }

  get length () {
    return this.h.length
  }
}

// Left rotation (without 0, 32, 64)
const rotlH = (h, l, s) => s > 32
  ? (l << (s - 32)) | (h >>> (64 - s))
  : (h << s) | (l >>> (32 - s))
const rotlL = (h, l, s) => s > 32
  ? (h << (s - 32)) | (l >>> (64 - s))
  : (l << s) | (h >>> (32 - s))

class KeccakP {
  #SHA3_PI
  #SHA3_ROTL
  #SHA3_IOTA_H
  #SHA3_IOTA_L

  constructor () {
    const _0n = BigInt(0)
    const _1n = BigInt(1)
    const _2n = BigInt(2)
    const _7n = BigInt(7)
    const _256n = BigInt(256)
    const _0x71n = BigInt(0x71)
    this.#SHA3_PI = []
    this.#SHA3_ROTL = []
    const _SHA3_IOTA = []

    for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
      // Pi
      [x, y] = [y, (2 * x + 3 * y) % 5]
      this.#SHA3_PI.push(2 * (5 * y + x))
      // Rotational
      this.#SHA3_ROTL.push((((round + 1) * (round + 2)) / 2) % 64)
      // Iota
      let t = _0n

      for (let j = 0; j < 7; j++) {
        R = ((R << _1n) ^ ((R >> _7n) * _0x71n)) % _256n
        if (R & _2n) t ^= _1n << ((_1n << BigInt(j)) - _1n)
      }

      _SHA3_IOTA.push(t)
    }

    const { h: SHA3_IOTA_H, l: SHA3_IOTA_L } = new U64Array(_SHA3_IOTA, true)

    this.#SHA3_IOTA_H = SHA3_IOTA_H
    this.#SHA3_IOTA_L = SHA3_IOTA_L
  }

  run (s, rounds = 24) {
    // console.log(s, s64)
    const B = new Uint32Array(5 * 2)
    // NOTE: all indices are x2 since we store state as u32 instead of u64 (bigints too slow in js)
    for (let round = 24 - rounds; round < 24; round++) {
      // Theta θ
      for (let x = 0; x < 10; x++) {
        B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40]
      }

      for (let x = 0; x < 10; x += 2) {
        const idx1 = (x + 8) % 10
        const idx0 = (x + 2) % 10
        const B0 = B[idx0]
        const B1 = B[idx0 + 1]
        const Th = rotlH(B0, B1, 1) ^ B[idx1]
        const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1]
        for (let y = 0; y < 50; y += 10) {
          s[x + y] ^= Th
          s[x + y + 1] ^= Tl
        }
      }

      // console.log(s, s64)
      // Rho (ρ) and Pi (π)
      let curH = s[2]
      let curL = s[3]

      for (let t = 0; t < 24; t++) {
        const shift = this.#SHA3_ROTL[t]
        const Th = rotlH(curH, curL, shift)
        const Tl = rotlL(curH, curL, shift)
        const PI = this.#SHA3_PI[t]
        curH = s[PI]
        curL = s[PI + 1]
        s[PI] = Th
        s[PI + 1] = Tl
      }

      // Chi (χ)
      for (let y = 0; y < 50; y += 10) {
        for (let x = 0; x < 10; x++) B[x] = s[y + x]
        for (let x = 0; x < 10; x++) s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10]
      }

      // Iota (ι)
      s[0] ^= this.#SHA3_IOTA_H[round]
      s[1] ^= this.#SHA3_IOTA_L[round]
    }

    B.fill(0)
  }
}

const keccak = new KeccakP()

export class SHA3Internal {
  state
  pos = 0
  posOut = 0
  finished = false
  state32
  rounds = 24
  destroyed = false
  blockLen
  outputLen
  suffix

  // NOTE: we accept arguments in bytes instead of bits here.
  constructor (blockLen, suffix, outputLen, enableXOF) {
    this.blockLen = blockLen
    this.outputLen = outputLen
    this.suffix = suffix // 0x06
    this.enableXOF = enableXOF || false
    // 1600 = 5x5 matrix of 64bit.  1600 bits === 200 bytes
    if (this.blockLen <= 0 || this.blockLen >= 200)
      throw new Error('Sha3 supports only keccak-f1600 function')
    this.state = new Uint8Array(200)
    this.state32 = new Uint32Array(
      this.state.buffer,
      this.state.byteOffset,
      Math.floor(this.state.byteLength / 4)
    )
  }

  keccak () {
    keccak.run(this.state32, this.rounds)
    this.posOut = 0
    this.pos = 0
  }

  update (data) {
    data = ByteView.from(data)
    const len = data.length
    for (let pos = 0; pos < len;) {
      const take = Math.min(this.blockLen - this.pos, len - pos)
      for (let i = 0; i < take; i++) this.state[this.pos++] ^= data[pos++]
      if (this.pos === this.blockLen) this.keccak()
    }
    return this
  }

  finish () {
    if (this.finished) return
    this.finished = true
    // Do the padding
    this.state[this.pos] ^= this.suffix
    if ((this.suffix & 0x80) !== 0 && this.pos === this.blockLen - 1) this.keccak()
    this.state[this.blockLen - 1] ^= 0x80
    this.keccak()
  }

  writeInto (out) {
    this.finish()
    const bufferOut = this.state
    for (let pos = 0, len = out.length; pos < len;) {
      if (this.posOut >= this.blockLen) this.keccak()
      const take = Math.min(this.blockLen - this.posOut, len - pos)
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos)
      this.posOut += take
      pos += take
    }
    return out
  }

  digestInto (out) {
    if (this.finished) throw new Error('digest() was already called')
    this.writeInto(out)
    this.destroy()
    return out
  }

  digest (encoding) {
    if (typeof encoding === 'undefined') {
      return this.digestInto(new ByteView(this.outputLen))
    } else if (encoding === 'hex') {
      return this.digestInto(new ByteView(this.outputLen)).toString('hex')
    } else if (encoding === 'base64') {
      return this.digestInto(new ByteView(this.outputLen)).toString('base64')
    } else if (encoding === 'base64url') {
      return this.digestInto(new ByteView(this.outputLen)).toString('base64url')
    } else if (encoding === 'base32') {
      return this.digestInto(new ByteView(this.outputLen)).toString('base32')
    } else if (encoding === 'base32crockford') {
      return this.digestInto(new ByteView(this.outputLen)).toString(
        'base32crockford'
      )
    }
  }

  destroy () {
    this.destroyed = true
    this.state.fill(0)
  }

  _cloneInto (to) {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this
    to ||= new SHA3Internal(blockLen, suffix, outputLen, enableXOF, rounds)
    to.state32.set(this.state32)
    to.pos = this.pos
    to.posOut = this.posOut
    to.finished = this.finished
    to.rounds = rounds
    // Suffix can change in cSHAKE
    to.suffix = suffix
    to.outputLen = outputLen
    to.enableXOF = enableXOF
    to.destroyed = this.destroyed
    return to
  }
}

export default class SHA3 {
  #internal

  constructor (hash) {
    if (hash instanceof SHA3Internal) {
      this.#internal = hash
      return
    }

    let blockLen
    let outputLen
    const suffix = 0x06

    switch (hash) {
      case '224':
        blockLen = 144
        outputLen = 28
        break
      case '256':
        blockLen = 136
        outputLen = 32
        break
      case '384':
        blockLen = 104
        outputLen = 48
        break
      case '512':
        blockLen = 72
        outputLen = 64
        break
      default:
        throw new Error('unrecognized hash')
    }

    this.#internal = new SHA3Internal(blockLen, suffix, outputLen, false)
  }

  update (buffer) {
    this.#internal.update(buffer)
    return this
  }

  digest (encoding) {
    return this.#internal.digest(encoding)
  }

  clone () {
    return new SHA3(this.#internal.clone())
  }
}

const POOL64URL = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'.split(''))

function isBase64Url (string) {
  let index = string.length

  while (--index >= 0) {
    if (POOL64URL.has(string[index]) === false) {
      return false
    }
  }

  return true
}

/* eslint-disable no-fallthrough */

export class SHA3Cipher {
  /** @type {ByteView} */
  #internal
  #saltLength

  constructor (cipherTextOrMessage, salt) {
    switch (typeof cipherTextOrMessage) {
      case 'string': {
        if (!isBase64Url(cipherTextOrMessage)) {
          throw new RangeError('cipherTextOrMessage must be a base64url encoded string')
        }

        cipherTextOrMessage = ByteView.from(cipherTextOrMessage, 'base64url')
      } // fallthrough

      case 'object': {
        if (!ByteView.isByteView(cipherTextOrMessage)) {
          throw new RangeError('cipherTextOrMessage must be a ByteView')
        }

        if (
          (cipherTextOrMessage.length > 32) &&
          cipherTextOrMessage.slice(0, 7).toString() === 'neusha3'
        ) {
          this.#internal = cipherTextOrMessage
          break
        }

        const saltType = typeof salt
        if (saltType === 'undefined') {
          salt = randomBytes(16)
        } else if (saltType === 'string') {
          if (!isBase64Url(salt)) {
            throw new RangeError('salt must be a base64url encoded string')
          }

          salt = ByteView.from(salt, 'base64url')
        } else if (!ByteView.isByteView(salt)) {
          throw new RangeError('salt must be a ByteView')
        } else if (salt.length > 32) {
          throw new RangeError('salt must have a length less than or equal to 32')
        }

        const hash = new SHA3('256')
        hash.update(cipherTextOrMessage)
        hash.update(salt)

        const header = [0x6E, 0x65, 0x75, 0x73, 0x68, 0x61, 0x33, 1, salt.length] // 9 16 25
        const headerAndSaltLength = 9 + salt.length
        this.#internal = new ByteView(headerAndSaltLength + 32)

        this.#internal.set(header, 0)
        this.#internal.set(salt, 9)
        this.#internal.set(hash.digest(), headerAndSaltLength)
        break
      }

      default:
        throw new RangeError('cipherTextOrMessage must be a base64url encoded string')
    }

    this.#saltLength = this.#internal[8]
  }

  get salt () {
    return this.#internal.slice(9, 9 + this.#saltLength)
  }

  get buffer () {
    return this.#internal.slice(9 + this.#saltLength)
  }

  compare (cipher) {
    if (!(cipher instanceof SHA3Cipher)) {
      throw new Error('expected cipher to be instance of SHA3Cipher')
    }

    const view = cipher.buffer
    const storedHash = this.buffer
    let index = Math.max(storedHash.length, view.length)
    let result = Number(storedHash.length !== view.length)

    while (--index >= 0) {
      result |= (storedHash[index] ^ view[index])
    }

    return result === 0
  }

  toString () {
    return this.#internal.toString('base64url')
  }

  inspect () {
    return `APISecretKey('${this}')`
  }

  [Symbol.for('nodejs.util.inspect.custom')] () {
    return `APISecretKey(\x1b[32m'${this}'\x1b[0m)`
  }

  [Symbol.toPrimitive] () {
    return this.toString()
  }
}
