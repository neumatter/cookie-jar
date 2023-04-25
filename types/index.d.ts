import { Duration } from "@neumatter/datetime";
import type ByteView from "byteview";
import type { IncomingMessage, ServerResponse } from 'http'

declare module "@neumatter/cookie-jar";

export interface CookieOptions {
  sameSite?: string|boolean
  maxAge?: number | string | Duration
  path?: string
  domain?: string
  expires?: Date
  httpOnly?: boolean
  secure?: boolean
}

export class Cookie {
  /**
   *
   * @param {string} name
   * @param {string} value
   * @param {CookieOptions} [options]
   */
  constructor (name: string, value: string, options: CookieOptions)
  name: string
  value: string
  get sameSite (): string | undefined
  set sameSite (value: boolean | 'lax' | 'none' | 'strict')
  get maxAge (): Duration | undefined
  set maxAge (value: number | string | Duration)
  get path (): string | undefined
  set path (value: string)
  get domain (): string | undefined
  set domain (value: string)
  get expires (): Date | undefined
  set expires (value: Date)
  get httpOnly (): boolean
  set httpOnly (value: boolean)
  get secure (): boolean
  set secure (value: boolean)
  inspect (): string
  toString (): string
}

export default class CookieJar {
  static isCookie (cookie: any): boolean
  static from (req: IncomingMessage): CookieJar

  constructor (input?: string | Array<Cookie> | Record<string, string | Cookie>)

  /**
   *
   * @param {string | Cookie} nameOrCookie
   * @param {string} value
   * @param {CookieOptions} options
   * @returns {this}
   */
  set (nameOrCookie: string | Cookie, value?: string, options?: CookieOptions): this

  delete (name: string): this

  /**
   *
   * @param {string} name
   * @returns {Cookie | null}
   */
  get (name: string): Cookie | null

  writeTo (response: ServerResponse): void

  sign (cookieName: string, secret: Uint8Array | ByteView): this

  /**
   *
   * @param {string} cookieName
   * @param {string} secret
   * @returns {string|false}
   */
  verify (cookieName: string, secret: Uint8Array | ByteView): string | false

  static serializeCookie (nameOrCookie: string | Cookie, value?: string, options?: CookieOptions): string

  static parseCookie (str: string): Cookie
}

export class RequestCookies {
  constructor (req: IncomingMessage)
}

export class ResponseCookies extends CookieJar {
  #res

  constructor (res: ServerResponse)
  set (nameOrCookie: string | Cookie, value: string, options: CookieOptions): this
  delete (name: string): this
  sign (cookieName: string, secret: Uint8Array | ByteView): this
}
