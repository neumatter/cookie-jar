
# CookieJar
[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard)

Module for working with cookies and/or signing and verifying cookies.
<br />

## Table of Contents
- [ Installation ](#install)
- [ Usage ](#usage)

<br />

<a name="install"></a>
## Install

```console
npm i @neumatter/cookie-jar
```

<br />

<a name="usage"></a>
## Usage


### CookieJar:

```js
import CookieJar from '@neumatter/cookie-jar'

const cookieJar = new CookieJar(req.get('cookie'))

cookieJar.set('id', {
  sameSite: true,
  httpOnly: true,
  strict: true
})
// ...use cookieJar
```


### Server Cookies:

```js
import { RequestCookies, ResponseCookies } from '@neumatter/cookie-jar'

const reqCookies = new RequestCookies(req)
const resCookies = new ResponseCookies(res) // Will set cookies automatically on Response

resCookies.set('id', {
  sameSite: 'lax',
  httpOnly: true,
  strict: true,
  maxAge: 'P2W' // 2 week duration string
})

resCookies.sign('id', secret) // Will update the value automatically on Response
```
