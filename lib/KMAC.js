
import ByteView from 'byteview'
import BVON from '@neumatter/bvon'
import { SHA3Internal } from './SHA3.js'

const BASE64URL_REGEX = /^[A-Za-z0-9\-_]*$/

function isBase64url (input) {
  if (typeof input !== 'string') {
    return false
  }

  return BASE64URL_REGEX.test(input)
}

// cSHAKE && KMAC (NIST SP800-185)
function leftEncode (n) {
  const res = [n & 0xff]
  n >>= 8

  while (n > 0) {
    res.unshift(n & 0xff)
    n >>= 8
  }

  res.unshift(res.length)
  return new ByteView(res)
}

function rightEncode (n) {
  const res = [n & 0xff]
  n >>= 8

  while (n > 0) {
    res.unshift(n & 0xff)
    n >>= 8
  }

  res.push(res.length)
  return new ByteView(res)
}

// NOTE: second modulo is necessary since we don't need to add padding if current element takes whole block
const getPadding = (len, block) => new ByteView((block - (len % block)) % block)
const toBytesOptional = buf => buf !== undefined ? ByteView.from(buf) : new ByteView([])

function cshakePers (hash, opts = {}) {
  if (!opts || (!opts.personalization && !opts.NISTfn)) return hash
  // Encode and pad inplace to avoid unneccesary memory copies/slices (so we don't need to zero them later)
  // bytepad(encode_string(N) || encode_string(S), 168)
  const blockLenBytes = leftEncode(hash.blockLen)
  const fn = toBytesOptional(opts.NISTfn)
  const fnLen = leftEncode(8 * fn.length) // length in bits
  const pers = toBytesOptional(opts.personalization)
  const persLen = leftEncode(8 * pers.length) // length in bits
  if (!fn.length && !pers.length) return hash
  hash.suffix = 0x04
  hash
    .update(blockLenBytes)
    .update(fnLen)
    .update(fn)
    .update(persLen)
    .update(pers)
  const totalLen =
    blockLenBytes.length +
    fnLen.length +
    fn.length +
    persLen.length +
    pers.length
  hash.update(getPadding(totalLen, hash.blockLen))
  return hash
}

class KMACInternal extends SHA3Internal {
  constructor (blockLen, outputLen, enableXOF, key, opts = {}) {
    super(blockLen, 0x1f, outputLen, enableXOF)
    this.#cshakePers({ NISTfn: 'KMAC', personalization: opts.personalization })
    if (!(key instanceof Uint8Array)) throw new TypeError('Secret key must be provided as a Uint8Array.')
    key = !ByteView.isByteView(key) ? ByteView.from(key) : key
    // 1. newX = bytepad(encode_string(K), 168) || X || right_encode(L).
    const blockLenBytes = leftEncode(this.blockLen)
    const keyLen = leftEncode(8 * key.length)
    this.update(blockLenBytes).update(keyLen).update(key)
    const totalLen = blockLenBytes.length + keyLen.length + key.length
    this.update(getPadding(totalLen, this.blockLen))
  }

  #cshakePers (opts = {}) {
    if (!opts || (!opts.personalization && !opts.NISTfn)) return this
    // Encode and pad inplace to avoid unneccesary memory copies/slices (so we don't need to zero them later)
    // bytepad(encode_string(N) || encode_string(S), 168)
    const blockLenBytes = leftEncode(this.blockLen)
    const fn = toBytesOptional(opts.NISTfn)
    const fnLen = leftEncode(8 * fn.length) // length in bits
    const pers = toBytesOptional(opts.personalization)
    const persLen = leftEncode(8 * pers.length) // length in bits
    if (!fn.length && !pers.length) return this
    this.suffix = 0x04
    this
      .update(blockLenBytes)
      .update(fnLen)
      .update(fn)
      .update(persLen)
      .update(pers)
    const totalLen =
      blockLenBytes.length +
      fnLen.length +
      fn.length +
      persLen.length +
      pers.length
    this.update(getPadding(totalLen, this.blockLen))
    return this
  }

  finish () {
    if (!this.finished) {
      this.update(rightEncode(this.enableXOF ? 0 : this.outputLen * 8)) // outputLen in bits
    }

    super.finish()
  }

  _cloneInto (to) {
    // Create new instance without calling constructor since key already in state and we don't know it.
    // Force "to" to be instance of KMAC instead of Sha3.
    if (!to) {
      to = Object.create(Object.getPrototypeOf(this), {})
      to.state = this.state.slice()
      to.blockLen = this.blockLen
      to.state32 = new Uint32Array(
        to.state.buffer,
        to.state.byteOffset,
        Math.floor(to.state.byteLength / 4)
      )
    }

    return super._cloneInto(to)
  }

  clone () {
    return this._cloneInto()
  }
}

export default class KMAC {
  #internal

  constructor (hash, key, opts = {}) {
    if (hash instanceof KMACInternal) {
      this.#internal = hash
      return
    }

    let blockLen
    let outputLen

    switch (hash) {
      case '128':
        blockLen = 168
        outputLen = 28
        break
      case '256':
        blockLen = 136
        outputLen = 32
        break
      default:
        throw new Error('unrecognized hash')
    }

    this.#internal = new KMACInternal(blockLen, outputLen, false, key, opts)
  }

  update (buffer) {
    this.#internal.update(buffer)
    return this
  }

  digest (encoding) {
    return this.#internal.digest(encoding)
  }

  clone () {
    return new KMAC(this.#internal.clone())
  }
}

const bwtSchema = new BVON.Schema({
  header: {
    algorithm: 'String',
    type: 'String'
  },
  payload: {
    expiration: 'Number',
    issuedAt: 'Number',
    bwtId: 'String',
    issuer: 'String',
    subject: 'String',
    audience: 'String'
  },
  signature: 'String'
})

class BWTBody {
  constructor (claims) {
    const timestamp = Date.now() / 1000 | 0
    const {
      expiresIn,
      expiration,
      issuedAt = timestamp,
      bwtId,
      issuer,
      subject,
      audience,
      ...restOfClaims
    } = claims

    if (bwtId !== undefined) {
      this.bwtId = bwtId
    }

    this.issuedAt = issuedAt

    if (expiration !== undefined) {
      this.expiration = expiration
    } else if (expiresIn !== undefined) {
      this.expiration = expiresIn + timestamp
    }

    if (issuer !== undefined) {
      this.issuer = issuer
    }

    if (subject !== undefined) {
      this.subject = subject
    }

    if (audience !== undefined) {
      this.audience = audience
    }

    Object.assign(this, restOfClaims)
  }
}

export class BWT {
  static #now () {
    return Date.now() / 1000 | 0
  }

  static verify (kjwt, secret) {
    const parts = kjwt.split('.')
    if (parts.length !== 3) {
      throw new Error('could not parse kjwt')
    } else if (!parts[2].length) {
      throw new Error('could not parse kjwt')
    }

    const header = ByteView.from(parts[0], 'base64url')
    const body = ByteView.from(parts[1], 'base64url')
    const payload = BVON.deserialize(body, bwtSchema)

    if (
      typeof payload.expiration === 'number' &&
      this.#now() > payload.expiration
    ) {
      return false
    }

    const kmac = new KMAC('256', secret)

    kmac.update(
      header.toString('base64url') +
      '.' +
      body.toString('base64url')
    )

    const view = kmac.digest()
    const storedHash = ByteView.from(parts[2], 'base64url')
    let index = Math.max(storedHash.length, view.length)
    let result = Number(storedHash.length !== view.length)

    while (--index >= 0) {
      result |= (storedHash[index] ^ view[index])
    }

    return result === 0
  }

  static sign (payload, secret, options = {}) {
    if (typeof payload !== 'object') {
      throw new Error('invalid payload')
    }

    const body = {}

    Object.assign(body, payload)

    const timestamp = Date.now() / 1000 | 0
    const {
      expiresIn,
      expiration,
      issuedAt = timestamp,
      bwtId,
      issuer,
      subject,
      audience
    } = options

    if (typeof expiration !== 'undefined') {
      body.expiration = expiration
    } else if (typeof expiresIn !== 'undefined') {
      body.expiration = expiresIn + timestamp
    }

    body.issuedAt = issuedAt

    if (typeof bwtId !== 'undefined') {
      body.bwtId = bwtId
    }

    if (typeof issuer !== 'undefined') {
      body.issuer = issuer
    }

    if (typeof subject !== 'undefined') {
      body.subject = subject
    }

    if (typeof audience !== 'undefined') {
      body.audience = audience
    }

    const bodySerialized = BVON
      .serialize(
        body,
        bwtSchema
      )
      .toString('base64url')

    const headerSerialized = BVON
      .serialize({
        algorithm: 'KS256',
        type: 'BWT'
      }, bwtSchema)
      .toString('base64url')

    const kmac = new KMAC('256', secret)

    kmac.update(
      headerSerialized +
      '.' +
      bodySerialized
    )

    const signature = kmac.digest('base64url')

    return new BWT(headerSerialized, bodySerialized, signature)
  }

  #header
  #payload
  #signature

  constructor (header, payload, signature) {
    if (!isBase64url(payload)) {
      throw new Error('invalid payload')
    }

    if (!isBase64url(header)) {
      throw new Error('invalid header')
    }

    if (!isBase64url(signature)) {
      throw new Error('invalid signature')
    }

    this.#header = header
    this.#payload = payload
    this.#signature = signature
  }

  get header () {
    return this.#header
  }

  get payload () {
    return this.#payload
  }

  get signature () {
    return this.#signature
  }

  inspect () {
    return `BWT('${this.toString()}')`
  }

  toJSON () {
    return this.toString()
  }

  toString () {
    return `${this.#header}.${this.#payload}.${this.#signature}`
  }
}
