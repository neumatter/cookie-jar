
import ByteView from 'byteview'
import toCamelCase from '@neumatter/to-camel-case'
import KMAC from './lib/KMAC.js'
import { Duration } from '@neumatter/datetime'

/** @typedef {{ sameSite: string|boolean, maxAge: number, path: string, domain: string, expires: Date, httpOnly: boolean, secure: boolean }} CookieOptions */

function isDate (val) {
  return val instanceof Date || Object.prototype.toString.call(val) === '[object Date]'
}

// const COMMENT_REGEX = /\s*\/\/.*$/g

const VALUE_REGEX = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/
// From RFC6265 S4.1.1
// note that it excludes \x3B ";"
const COOKIE_OCTETS = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+$/

const CONTROL_CHARS = /[\x00-\x1F]/

// From Chromium // '\r', '\n' and '\0' should be treated as a terminator in
// the "relaxed" mode, see:
// https://github.com/ChromiumWebApps/chromium/blob/b3d3b4da8bb94c1b2e061600df106d590fda3620/net/cookies/parsed_cookie.cc#L60
const TERMINATORS = ["\n", "\r", "\0"]

// RFC6265 S4.1.1 defines path value as 'any CHAR except CTLs or ";"'
// Note ';' is \x3B
const PATH_VALUE = /[\x20-\x3A\x3C-\x7E]+/

// date-time parsing constants (RFC6265 S5.1.1)

const MAX_TIME = 2147483647000 // 31-bit max
const MIN_TIME = 0

// Dumped from ip-regex@4.0.0, with the following changes:
// * all capturing groups converted to non-capturing -- "(?:)"
// * support for IPv6 Scoped Literal ("%eth1") removed
// * lowercase hexadecimal only
const IP_REGEX_LOWERCASE = /(?:^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$)|(?:^(?:(?:[a-f\d]{1,4}:){7}(?:[a-f\d]{1,4}|:)|(?:[a-f\d]{1,4}:){6}(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|:[a-f\d]{1,4}|:)|(?:[a-f\d]{1,4}:){5}(?::(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-f\d]{1,4}){1,2}|:)|(?:[a-f\d]{1,4}:){4}(?:(?::[a-f\d]{1,4}){0,1}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-f\d]{1,4}){1,3}|:)|(?:[a-f\d]{1,4}:){3}(?:(?::[a-f\d]{1,4}){0,2}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-f\d]{1,4}){1,4}|:)|(?:[a-f\d]{1,4}:){2}(?:(?::[a-f\d]{1,4}){0,3}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-f\d]{1,4}){1,5}|:)|(?:[a-f\d]{1,4}:){1}(?:(?::[a-f\d]{1,4}){0,4}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-f\d]{1,4}){1,6}|:)|(?::(?:(?::[a-f\d]{1,4}){0,5}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-f\d]{1,4}){1,7}|:)))$)/
const IP_V6_REGEX_STRING = (
  '\\[?(?:(?:[a-fA-F\\d]{1,4}:){7}(?:[a-fA-F\\d]{1,4}|:)|' +
  '(?:[a-fA-F\\d]{1,4}:){6}(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d' +
  '|[1-9]\\d|\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]' +
  '\\d|\\d)){3}|:[a-fA-F\\d]{1,4}|:)|(?:[a-fA-F\\d]{1,4}:)' +
  '{5}(?::(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(?:\\.(' +
  '?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}|(?::[a-fA-F' +
  '\\d]{1,4}){1,2}|:)|(?:[a-fA-F\\d]{1,4}:){4}(?:(?::[a-fA-F' +
  '\\d]{1,4}){0,1}:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)' +
  '(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}|(?::[a' +
  '-fA-F\\d]{1,4}){1,3}|:)|(?:[a-fA-F\\d]{1,4}:){3}(?:(?::[a-fA' +
  '-F\\d]{1,4}){0,2}:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)' +
  '(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}|(?::[a-f' +
  'A-F\\d]{1,4}){1,4}|:)|(?:[a-fA-F\\d]{1,4}:){2}(?:(?::[a-fA-F' +
  '\\d]{1,4}){0,3}:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(?' +
  ':\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}|(?::[a-fA' +
  '-F\\d]{1,4}){1,5}|:)|(?:[a-fA-F\\d]{1,4}:){1}(?:(?::[a-fA-F' +
  '\\d]{1,4}){0,4}:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(' +
  '?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)){3}|(?::[a-f' +
  'A-F\\d]{1,4}){1,6}|:)|(?::(?:(?::[a-fA-F\\d]{1,4}){0,5}:(?:25' +
  '[0-5]|2[0-4]\\d|1\\d\\d|[1-9]\\d|\\d)(?:\\.(?:25[0-5]|2[0-4]\\' +
  'd|1\\d\\d|[1-9]\\d|\\d)){3}|(?::[a-fA-F\\d]{1,4}){1,7}|:)))(?:' +
  '%[0-9a-zA-Z]{1,})?\\]?'
)

const IP_V6_REGEX = new RegExp(`^${IP_V6_REGEX_STRING}$`)
const SYMBOL_COOKIE = Symbol.for('neumatter.cookie')

const NON_ASCII_REGEX = /[^\0-\x7F]/ // Note: U+007F DEL is excluded too.
const SEPARATORS_REGEX = /[\x2E\u3002\uFF0E\uFF61]/g // RFC 3490 separators

function domainToASCII (domain) {
  const parts = domain.split('@')
  let result = ''
  if (parts.length > 1) {
    // In email addresses, only the domain name should be punycoded. Leave
    // the local part (i.e. everything up to `@`) intact.
    result = parts[0] + '@'
    domain = parts[1]
  }
  // Avoid `split(regex)` for IE8 compatibility. See #17.
  domain = domain.replace(SEPARATORS_REGEX, '\x2E')
  const labels = domain.split('.')
  const encoded = labels.reduce((encodedLabels, label) => {
    if (!NON_ASCII_REGEX.test(label)) {
      encodedLabels += encodedLabels.length ? `.${label}` : label
      return encodedLabels
    }

    const output = []

    // Convert the input in UCS-2 to an array of Unicode code points.
    const input = convertUCS2ToUTF16(label)

    // Cache the length.
    const inputLength = input.length

    // Initialize the state.
    let n = 0x80
    let delta = 0
    let bias = 72

    // Handle the basic code points.
    for (const currentValue of input) {
      if (currentValue < 0x80) {
        output.push(String.fromCodePoint(currentValue))
      }
    }

    const basicLength = output.length
    let handledCPCount = basicLength

    // `handledCPCount` is the number of code points that have been handled;
    // `basicLength` is the number of basic code points.

    // Finish the basic string with a delimiter unless it's empty.
    if (basicLength) {
      output.push('-')
    }

    // Main encoding loop:
    while (handledCPCount < inputLength) {
      // All non-basic code points < n have been handled already. Find the next
      // larger one:
      let m = 0x7FFFFFFF
      for (const currentValue of input) {
        if (currentValue >= n && currentValue < m) {
          m = currentValue
        }
      }

      // Increase `delta` enough to advance the decoder's <n,i> state to <m,0>,
      // but guard against overflow.
      const handledCPCountPlusOne = handledCPCount + 1
      if (m - n > Math.floor((0x7FFFFFFF - delta) / handledCPCountPlusOne)) {
        throw new Error('overflow')
      }

      delta += (m - n) * handledCPCountPlusOne
      n = m

      for (const currentValue of input) {
        if (currentValue < n && ++delta > 0x7FFFFFFF) {
          throw new Error('overflow')
        }
        if (currentValue === n) {
          // Represent delta as a generalized variable-length integer.
          let q = delta
          for (let k = 36; ; k += 36) {
            const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias
            if (q < t) {
              break
            }
            const qMinusT = q - t
            const baseMinusT = 36 - t
            const currentDigit = t + (qMinusT % baseMinusT)
            output.push(
              String.fromCodePoint(currentDigit + 22 + 75 * (currentDigit < 26) - (false << 5))
            )
            q = Math.floor(qMinusT / baseMinusT)
          }
          // digitToBasic = (digit, flag) => digit + 22 + 75 * (digit < 26) - ((flag != 0) << 5)
          output.push(String.fromCodePoint(q + 22 + 75 * (q < 26) - (false << 5)))
          let k = 0
          delta = handledCPCount === basicLength ? Math.floor(delta / 700) : delta >> 1
          delta += Math.floor(delta / handledCPCountPlusOne)
          for (/* no initialization */; delta > 35 * 26 >> 1; k += 36) {
            delta = Math.floor(delta / 35)
          }
          bias = delta
          delta = 0
          ++handledCPCount
        }
      }

      ++delta
      ++n
    }
    const res = output.join('')
    encodedLabels += encodedLabels.length ? `.${res}` : res
    return encodedLabels
  }, '')

  return 'xn--' + result + encoded
}

function convertUCS2ToUTF16 (string) {
  const output = []
  let counter = -1
  const length = string.length

  while (++counter < length) {
    const value = string.codePointAt(counter)
    if (value > 0xE000) ++counter
    output.push(value)
  }

  return output
}

// S5.1.2 Canonicalized Host Names
function canonicalizeDomain (str) {
  if (str === undefined || str === null) {
    return undefined
  }

  str = str.trim().replace(/^\./, '') // S4.1.2.3 & S5.2.3: ignore leading .

  if (IP_V6_REGEX.test(str)) {
    str = str.replace('[', '').replace(']', '')
  }

  // convert to IDN if any non-ASCII characters
  if (/[^\u0001-\u007f]/.test(str)) {
    str = domainToASCII(str)
  }

  return str.toLowerCase()
}

export class Cookie {
  #config

  /**
   *
   * @param {string} name
   * @param {string} value
   * @param {CookieOptions} [options]
   */
  constructor (name, value, options) {
    options = options === undefined ? {} : options
    this.name = name
    this.value = value
    this.#config = new Map()

    if (options.sameSite) {
      this.sameSite = options.sameSite
    }
    if (options.sameSite === undefined) {
      this.sameSite = true
    }
    if (options.maxAge !== undefined) {
      this.maxAge = options.maxAge
    }
    if (options.path) {
      this.path = options.path
    } else if (options.path === undefined) {
      this.path = '/'
    }
    if (options.domain) {
      this.domain = options.domain
    }
    if (options.expires && isDate(options.expires)) {
      this.expires = options.expires
    }
    if (options.httpOnly === undefined || options.httpOnly === true) {
      this.httpOnly = true
    }
    if (options.secure === true) {
      this.sameSite = true
    }
  }

  get sameSite () {
    const sameSite = this.#config.get('sameSite')
    return sameSite !== undefined && sameSite.split('=')[1].toLowerCase()
  }

  set sameSite (value) {
    if (value === true) {
      this.#config.set('sameSite', 'SameSite=Strict')
    } else if (typeof value === 'string') {
      switch (value) {
        case 'lax':
          this.#config.set('sameSite', 'SameSite=Lax')
          break
        case 'none':
          this.#config.set('sameSite', 'SameSite=None')
          break
        case 'strict':
          this.#config.set('sameSite', 'SameSite=Strict')
          break
        default:
          throw new RangeError(`Cookie.sameSite recieved invalid valueof ${value}`)
      }
    }
  }

  get maxAge () {
    const value = this.#config.get('maxAge')

    if (value === undefined) {
      return value
    }

    return Duration.from({ seconds: Number(value.slice(8)) })
  }

  set maxAge (value) {
    switch (typeof value) {
      case 'string':
        value = Duration.from(value).round({ largestUnit: 'second' }).seconds
        break
      case 'object':
        value = Duration.from(value).round({ largestUnit: 'second' }).seconds
        break
      case 'number':
        value = value === Infinity || -Infinity ? value.toString() : Math.floor(value)
        break
      default:
        throw new TypeError('Cookie.maxAge recieved invalid type')
    }

    this.#config.set('maxAge', `Max-Age=${value}`)
  }

  get path () {
    const value = this.#config.get('path')

    if (value === undefined) {
      return value
    }

    return value.slice(5)
  }

  set path (value) {
    value = String(value)

    if (!PATH_VALUE.test(value)) {
      throw new RangeError(`invalid path ${value}`)
    }

    this.#config.set('path', `Path=${value}`)
  }

  get domain () {
    const value = this.#config.get('domain')

    if (value === undefined) {
      return value
    }

    return value.slice(7)
  }

  set domain (value) {
    value = canonicalizeDomain(String(value))
    this.#config.set('domain', `Domain=${value}`)
  }

  get expires () {
    const value = this.#config.get('expires')

    if (value === undefined) {
      return value
    }

    return new Date(value.slice(8))
  }

  set expires (value) {
    if (!isDate(value)) {
      throw new RangeError('Cookie.expires should be an instanceof Date')
    }

    this.#config.set('expires', `Expires=${value.toUTCString()}`)
  }

  get httpOnly () {
    const value = this.#config.get('httpOnly')

    if (value === undefined) {
      return false
    }

    return true
  }

  set httpOnly (value) {
    value = Boolean(value)
    if (value) {
      this.#config.set('httpOnly', 'HttpOnly')
    } else {
      this.#config.delete('httpOnly')
    }
  }

  get secure () {
    const value = this.#config.get('secure')

    if (value === undefined) {
      return false
    }

    return true
  }

  set secure (value) {
    value = Boolean(value)
    if (value) {
      this.#config.set('secure', 'Secure')
    } else {
      this.#config.delete('secure')
    }
  }

  get [SYMBOL_COOKIE] () {
    return true
  }

  [Symbol.toPrimitive] (hint) {
    return hint === 'number' ? NaN : this.toString()
  }

  inspect () {
    return `<Cookie ${this.toString()} />`
  }

  [Symbol.for('nodejs.util.inspect.custom')] () {
    return this.inspect()
  }

  toString () {
    const value = encodeCookieComponent(this.value)
    let string = `${this.name}=${value}`

    for (const entry of this.#config.values()) {
      string += `; ${entry}`
    }

    return string
  }
}

export default class CookieJar {
  static isCookie (cookie) {
    if (typeof cookie !== 'object') {
      return false
    }

    return typeof cookie[SYMBOL_COOKIE] === 'boolean'
  }

  static from (req) {
    const cookieString = typeof req.get === 'function'
      ? req.get('cookie') || req.headers.cookie
      : req.headers.cookie

    if (typeof cookieString !== 'string') {
      return new CookieJar()
    }

    const cookies = []
    const parts = cookieString.split(';')
    const { length } = cookies
    let index = -1

    while (++index < length) {
      const [key, value] = parts[index].trim().split('=')
      cookies[index] = new Cookie(key.trim(), decodeCookieComponent(value.trim()))
    }

    return new CookieJar(cookies)
  }

  #set = new Set()

  constructor (input) {
    const type = typeof input
    if (type === 'string') {
      const cookies = input.split(';')
      const { length } = cookies
      let index = -1

      while (++index < length) {
        const [key, value] = cookies[index].trim().split('=')
        this[key] = new Cookie(key.trim(), decodeCookieComponent(value.trim()))
      }
    } else if (input === null || type === 'undefined') {
      return this
    } else if (type === 'object' && Array.isArray(input)) {
      let index = input.length

      while (--index > -1) {
        const cookie = input[index]
        if (CookieJar.isCookie(cookie) !== true) {
          throw new TypeError('new CookieJar expected a typeof Array<Cookie>')
        }
        this[cookie.name] = cookie
      }
    } else if (type === 'object') {
      if (input instanceof CookieJar) {
        return input
      } else {
        const keys = Object.keys(input)
        const { length } = keys
        let index = -1

        while (++index < length) {
          const entry = input[keys[index]]
          const entryType = typeof entry
          if (entryType === 'string') {
            const cookieEntry = CookieJar.parseCookie(entry)
            this[cookieEntry.name] = cookieEntry
          } else if (entry instanceof Cookie) {
            this[entry.name] = entry
          }
        }
      }
    }
  }

  /**
   *
   * @param {string | Cookie} nameOrCookie
   * @param {string} value
   * @param {CookieOptions} options
   * @returns {this}
   */
  set (nameOrCookie, value, options) {
    const cookie = CookieJar.isCookie(nameOrCookie) ? nameOrCookie : new Cookie(nameOrCookie, value, options)
    this[cookie.name] = cookie
    this.#set.add(cookie.name)
    return this
  }

  delete (name) {
    const cookie = this.get(name)

    if (cookie === null) {
      return this
    }

    const { value } = cookie

    this.set(name, value, {
      expires: new Date()
    })
  }

  /**
   *
   * @param {string} name
   * @returns {Cookie | null}
   */
  get (name) {
    return this[name] || null
  }

  writeTo (response) {
    const cookies = []

    for (const cookieName of this.#set.values()) {
      const cookie = this[cookieName]
      cookies.push(cookie.toString())
    }

    response.setHeader('Set-Cookie', cookies)
  }

  sign (cookieName, secret) {
    if (!this[cookieName]) return this
    const value = this[cookieName].value
    const kmac = new KMAC('256', secret)
    kmac.update(ByteView.from(value))
    // const hmac = createHmac('sha256', secret).update(value).digest()
    const bv = kmac.digest('base64url')
    this[cookieName].value = `${value}.${bv}`
    return this
  }

  /**
   *
   * @param {string} cookieName
   * @param {string} secret
   * @returns {string|false}
   */
  verify (cookieName, secret) {
    const cookie = this.get(cookieName)
    if (!secret) throw new TypeError('Secret key must be provided.')
    if (!cookie) return false
    const indexOfDot = cookie.value.lastIndexOf('.')
    const val = cookie.value.slice(0, indexOfDot)
    const originalHash = ByteView.from(cookie.value.slice(indexOfDot + 1), 'base64url')
    const expectedHash = new KMAC('256', secret).update(ByteView.from(val)).digest()

    try {
      let index = Math.max(originalHash.length, expectedHash.length)
      let result = Number(originalHash.length !== expectedHash.length)

      while (--index >= 0) {
        result |= (originalHash[index] ^ expectedHash[index])
      }

      return result === 0 ? val : false
    } catch (err) {
      return false
    }
  }

  /**
   *
   * @param {[name: string, value: string, options: CookieOptions ]} args
   */
  static serializeCookie (...args) {
    return new Cookie(...args).toString()
  }

  static parseCookie (str) {
    const cookieEntries = str.split(';')
    const { length: cookieEntryLength } = cookieEntries
    let name = ''
    let value = ''
    const options = {}
    let cookieEntryIndex = -1

    while (++cookieEntryIndex < cookieEntryLength) {
      const cookieEntry = cookieEntries[cookieEntryIndex].trim()
      let equalIndex = cookieEntry.indexOf('=')
      if (cookieEntryIndex === 0) {
        name = cookieEntry.slice(0, equalIndex)
        value = cookieEntry.slice(++equalIndex)
        continue
      }

      if (equalIndex === -1) {
        const option = toCamelCase(cookieEntry)
        options[option] = true
        continue
      }

      const option = toCamelCase(cookieEntry.slice(0, equalIndex))
      const optionValue = cookieEntry.slice(++equalIndex)

      switch (option) {
        case 'maxAge':
          options[option] = Number(optionValue)
          break
        case 'expires':
          options[option] = new Date(optionValue)
          break
        default:
          options[option] = optionValue
          break
      }
    }

    return new Cookie(name, value, options)
  }
}

export class RequestCookies {
  constructor (req) {
    if (typeof req !== 'object' || typeof req.headers !== 'object') {
      throw new RangeError('RequestCookies must include res')
    }
    const input = typeof req.get === 'function'
      ? req.get('cookie') || req.headers.cookie
      : req.headers.cookie

    const cookies = input.split(';')
    const { length } = cookies
    let index = -1

    while (++index < length) {
      const [key, value] = cookies[index].trim().split('=')
      this[key] = new Cookie(key.trim(), decodeCookieComponent(value.trim()))
    }
  }
}

export class ResponseCookies extends CookieJar {
  #res

  constructor (res) {
    super()
    if (typeof res !== 'object' || typeof res.setHeader !== 'function') {
      throw new RangeError('ResponseCookies must include res')
    }
    const setCookie = res.getHeader('set-cookie')
    this.#res = res

    let cookieJarInput
    if (typeof setCookie === 'string') {
      try {
        const cookie = CookieJar.parseCookie(setCookie)
        cookieJarInput = [cookie]
      } catch {
        cookieJarInput = undefined
      }
    } else if (typeof setCookie === 'object' && Array.isArray(setCookie)) {
      try {
        const cookies = []
        for (const cookie of setCookie) {
          cookies.push(CookieJar.parseCookie(cookie))
        }
        cookieJarInput = cookies
      } catch {
        cookieJarInput = undefined
      }
    }

    if (cookieJarInput !== undefined) {
      for (const cookieInstance of cookieJarInput) {
        this.set(cookieInstance)
      }
    }
  }

  /**
   *
   * @param {string | Cookie} nameOrCookie
   * @param {string} value
   * @param {CookieOptions} options
   * @returns {this}
   */
  set (nameOrCookie, value, options) {
    super.set(nameOrCookie, value, options)
    this.writeTo(this.#res)
    return this
  }

  /**
   *
   * @param {string} name
   * @returns {this}
   */
  delete (name) {
    super.delete(name)
    this.writeTo(this.#res)
    return this
  }

  /**
   *
   * @param {string} cookieName
   * @param {Uint8Array} secret
   * @returns {this}
   */
  sign (cookieName, secret) {
    super.sign(cookieName, secret)
    this.writeTo(this.#res)
    return this
  }
}

const WHITE_SPACE_ENCODED = [
  ['%3B', ';'],
  ['%2C', ','],
  ['%09', '\t'],
  ['%0A', '\n'],
  ['%0B', '\v'],
  ['%0C', '\f'],
  ['%0D', '\r'],
  ['%20', ' '],
  ['%C2%85', '\u0085'],
  ['%C2%A0', '\u00A0'],
  ['%E1%9A%80', '\u1680'],
  ['%E2%80%80', '\u2000'],
  ['%E2%80%81', '\u2001'],
  ['%E2%80%82', '\u2002'],
  ['%E2%80%83', '\u2003'],
  ['%E2%80%84', '\u2004'],
  ['%E2%80%85', '\u2005'],
  ['%E2%80%86', '\u2006'],
  ['%E2%80%87', '\u2007'],
  ['%E2%80%88', '\u2008'],
  ['%E2%80%89', '\u2009'],
  ['%E2%80%8A', '\u200A'],
  ['%E2%80%A8', '\u2028'],
  ['%E2%80%A9', '\u2029'],
  ['%E2%80%AF', '\u202F'],
  ['%E2%81%9F', '\u205F'],
  ['%E3%80%80', '\u3000']
]

/**
 *
 * @param {string} str
 * @returns {string}
 */
function decodeCookieComponent (str) {
  let { length: index } = WHITE_SPACE_ENCODED

  while (--index >= 0) {
    const [encodedChars, decodedChar] = WHITE_SPACE_ENCODED[index]
    const indexOfChars = str.indexOf(encodedChars)
    const endOfEncodedChars = indexOfChars + encodedChars.length
    if (indexOfChars > 0) {
      str = (endOfEncodedChars === str.length)
        ? (
            str.slice(0, indexOfChars) +
            decodedChar
          )
        : (
            str.slice(0, indexOfChars) +
            decodedChar +
            str.slice(endOfEncodedChars)
          )
    } else if (indexOfChars === 0) {
      str = (
        decodedChar +
        str.slice(endOfEncodedChars)
      )
    }
  }

  return str
}

/**
 *
 * @param {string} str
 * @returns {string}
 */
function encodeCookieComponent (str) {
  const arr = str.split('')
  let { length: index } = arr

  while (--index >= 0) {
    switch (arr[index]) {
      case ';':
        arr[index] = '%3B'
        break
      case ',':
        arr[index] = '%2C'
        break
      case '\t':
        arr[index] = '%09'
        break
      case '\n':
        arr[index] = '%0A'
        break
      case '\v':
        arr[index] = '%0B'
        break
      case '\f':
        arr[index] = '%0C'
        break
      case '\r':
        arr[index] = '%0D'
        break
      case ' ':
        arr[index] = '%20'
        break
      case '\u0085':
        arr[index] = '%C2%85'
        break
      case '\u00A0':
        arr[index] = '%C2%A0'
        break
      case '\u1680':
        arr[index] = '%E1%9A%80'
        break
      case '\u2000':
        arr[index] = '%E2%80%80'
        break
      case '\u2001':
        arr[index] = '%E2%80%81'
        break
      case '\u2002':
        arr[index] = '%E2%80%82'
        break
      case '\u2003':
        arr[index] = '%E2%80%83'
        break
      case '\u2004':
        arr[index] = '%E2%80%84'
        break
      case '\u2005':
        arr[index] = '%E2%80%85'
        break
      case '\u2006':
        arr[index] = '%E2%80%86'
        break
      case '\u2007':
        arr[index] = '%E2%80%87'
        break
      case '\u2008':
        arr[index] = '%E2%80%88'
        break
      case '\u2009':
        arr[index] = '%E2%80%89'
        break
      case '\u200A':
        arr[index] = '%E2%80%8A'
        break
      case '\u2028':
        arr[index] = '%E2%80%A8'
        break
      case '\u2029':
        arr[index] = '%E2%80%A9'
        break
      case '\u202F':
        arr[index] = '%E2%80%AF'
        break
      case '\u205F':
        arr[index] = '%E2%81%9F'
        break
      case '\u3000':
        arr[index] = '%E3%80%80'
        break
      default:
        break
    }
  }

  return arr.join('')
}
