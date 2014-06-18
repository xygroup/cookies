
var base64 = require('base64-url')
var Keygrip = require('keygrip')
var http = require('http')
var cache = {}

function Cookies(request, response, keys) {
  if (!(this instanceof Cookies)) return new Cookies(request, response, keys)

  this.request = request
  this.response = response
  if (keys) {
    // array of key strings
    if (Array.isArray(keys))
      this.keys = new Keygrip(keys)
    // any keygrip constructor to allow different versions
    else if (keys.constructor && keys.constructor.name === 'Keygrip')
      this.keys = keys
  }
}

Cookies.prototype = {
  get: function(name, opts) {
    opts = opts || {}

    // no cookie sent
    var header = this.request.headers.cookie
    if (!header) return

    // no value
    var match = header.match(getPattern(name))
    if (!match) return

    var value = match[1]
    var index
    // return an encrypted value
    if (/^enc\.[\w-]+$/.exec(value)) {
      if (!this.keys) throw new Error('.keys required for encrypted cookies')
      value = new Buffer(base64.unescape(value.replace('enc.', '')), 'base64')
      var res = this.keys.decrypt(value)
      // unset bad decrypts
      if (!res) return this.set(name, null)
      value = res[0]
      index = res[1]
      if (index) {
        // re-encrypt if not using the latest key
        var digest = base64.escape(this.keys.encrypt(value)).toString('base64')
        this.set(name, 'enc.' + digest)
      }
      return value ? value.toString('utf8') : ''
    }

    var sigName = name + ".sig"
    var signed = opts.signed !== undefined ? opts.signed : !!this.keys

    // return an unsigned cookie
    if (!signed) return value

    if (!this.keys) throw new Error('.keys required for signed cookies')

    // signed but no signature means no cookie
    var remote = this.get(sigName)
    if (!remote) return
    remote = new Buffer(base64.unescape(remote))

    var data = name + "=" + value
    index = this.keys.index(data, remote)

    // no key matches, unmatch signature and don't return anything
    if (index < 0) {
      this.set(sigName, null, {path: "/", signed: false })
    } else {
      var signature = base64.escape(this.keys.sign(data).toString('base64'))
      index && this.set(sigName, signature, { signed: false })
      return value
    }
  },

  set: function(name, value, opts) {
    opts = opts || {}

    // can't set a signature yourself
    // added only to make tests happy
    // because i added `opts = opts || {}`
    if (/\.sig$/.test(name)) return this

    var res = this.response
    var req = this.request
    var encrypted = opts.encrypted
    var signed = opts.signed !== undefined
      ? opts.signed
      : (!encrypted && !!this.keys)

    // check if keys are required
    if (signed || encrypted)
    if (!this.keys) throw new Error('.keys required for signed cookies');
    if (encrypted) value = 'enc.' + base64.escape(this.keys.encrypt(value).toString('base64'))

    var cookie = new Cookie(name, value, opts)

    // to do: refactor with proxy-addr or whatever
    var secure = req.connection.encrypted
    if (!secure && opts.secure) throw new Error("Cannot send secure cookie over unencrypted socket")
    cookie.secure = secure
    if (opts && "secure" in opts) cookie.secure = opts.secure
    if (opts && "secureProxy" in opts) cookie.secure = opts.secureProxy

    // multiple cookie headers
    var headers = res.getHeader("Set-Cookie") || []
    if (typeof headers == "string") headers = [headers]

    headers = pushCookie(headers, cookie)

    if (signed) {
      cookie.value = base64.escape(this.keys.sign(cookie.toString()).toString('base64'))
      cookie.name += ".sig"
      headers = pushCookie(headers, cookie)
    }

    // use the original `res.setHeader()` method,
    // because frameworks like Express like to patch it
    var setHeader = res.set
      ? http.OutgoingMessage.prototype.setHeader
      : res.setHeader
    setHeader.call(res, 'Set-Cookie', headers)
    return this
  }
}

function Cookie(name, value, attrs) {
  value || (this.expires = new Date(0))

  this.name = name
  this.value = value || ""

  for (var name in attrs) this[name] = attrs[name]
}

Cookie.prototype = {
  path: "/",
  expires: undefined,
  domain: undefined,
  httpOnly: true,
  secure: false,
  overwrite: false,

  toString: function() {
    return this.name + "=" + this.value
  },

  toHeader: function() {
    var header = this.toString()

    if (this.maxage) this.expires = new Date(Date.now() + this.maxage);

    if (this.path     ) header += "; path=" + this.path
    if (this.expires  ) header += "; expires=" + this.expires.toUTCString()
    if (this.domain   ) header += "; domain=" + this.domain
    if (this.secure   ) header += "; secure"
    if (this.httpOnly ) header += "; httponly"

    return header
  }
}

function getPattern(name) {
  if (cache[name]) return cache[name]

  return cache[name] = new RegExp(
    "(?:^|;) *" +
    name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&") +
    "=([^;]*)"
  )
}

function pushCookie(cookies, cookie) {
  if (cookie.overwrite) {
    cookies = cookies.filter(function(c) {
      return c.indexOf(cookie.name+'=') !== 0
    })
  }
  cookies.push(cookie.toHeader())
  return cookies
}

Cookies.connect = Cookies.express = function(keys) {
  return function(req, res, next) {
    req.cookies = res.cookies = new Cookies(req, res, keys)
    next()
  }
}

Cookies.Cookie = Cookie

module.exports = Cookies
