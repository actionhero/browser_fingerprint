var crypto = require('crypto')
var os = require('os')

var browserFingerprint = {

  fingerprint: function (req, options, callback) {
    // The goal is to come up with as many *potentially* unique traits for the connection and add them to the elementsHash.
    // The collection of all the elementsHash keys will *hopefully* be unique enough for fingerprinting
    // Then, we save this hash in a cookie for later retrieval

    var defaults = {
      cookieKey: '__browser_fingerprint',
      toSetCookie: true,
      onlyStaticElements: false
    }

    if (typeof options === 'function') { callback = options; options = null }
    for (var i in defaults) {
      if (options[i] == null) { options[i] = defaults[i] }
    }

    var fingerprint
    var key
    var value

    var cookies = this.parseCookies(req)
    if (cookies[options.cookieKey] != null) {
      fingerprint = cookies[options.cookieKey]
      return callback(null, fingerprint, {clientCookie: fingerprint}, {})
    } else if (req.headers[options.cookieKey] != null) {
      fingerprint = req.headers[options.cookieKey]
      return callback(null, fingerprint, {clientCookie: fingerprint}, {})
    } else if (req.headers[('x-' + options.cookieKey).toLowerCase()] != null) {
      fingerprint = req.headers[('x-' + options.cookieKey).toLowerCase()]
      return callback(null, fingerprint, {clientCookie: fingerprint}, {})
    } else {
      var remoteAddress = req.headers['x-forwarded-for']
      if (remoteAddress == null) { remoteAddress = req.connection.remoteAddress }

      var elementsHash = {
        httpVersion: req.httpVersion,
        remoteAddress: remoteAddress,
        cookieKey: options.cookieKey,
        hashedHostName: this.hashedHostName()
      }

      // these elements add greater entropy to the fingerprint, but aren't gaurnteed to be the same uppon each request
      if (options.onlyStaticElements !== true) {
        elementsHash.remotePort = req.connection.remotePort
        elementsHash.rand = Math.random()
        elementsHash.time = new Date().getTime()
        elementsHash.hashedPid = this.hashedPid()
      };

      for (var j in req.headers) {
        if (options.onlyStaticElements && (j === 'cookie' || j === 'referer')) { continue }
        key = 'header_' + j
        elementsHash[key] = req.headers[j]
      }

      elementsHash = this.sortAndStringObject(elementsHash)
      fingerprint = this.calculateHashFromElemets(elementsHash)

      var cookeHash = {}
      if (options.toSetCookie === true) {
        if (options.settings !== undefined && options.settings !== null) {
          var settings = options.settings
          var settingsParams = ''
          /*
          new version in object format e.g.
          settings : {path : '/', expires : 86400000 }

          old version till v0.0.4 e.g.
          settings :'path=/;expires=' + new Date(new Date().getTime() + 86400000).toUTCString()+';'
          */

          /* Check to be compatible to both version */
          if (typeof (settings) === 'object') {
            for (key in settings) {
              if (settings.hasOwnProperty(key)) {
                value = settings[key]
                if (key === 'expires') {
                  value = new Date(new Date().getTime() + settings[key]).toUTCString()
                }
                settingsParams = settingsParams + key + '=' + value + ';'
              }
            }
          } else {
            settingsParams = settings
          }
          cookeHash = { 'Set-Cookie': options.cookieKey + '=' + fingerprint + ';' + settingsParams }
        } else {
          cookeHash = { 'Set-Cookie': options.cookieKey + '=' + fingerprint }
        }
      }

      return callback(null, fingerprint, elementsHash, cookeHash)
    }
  },

  savedHashedHostName: null,
  hashedHostName: function () {
    if (this.savedHashedHostName != null) {
      return this.savedHashedHostName
    } else {
      var md5sum = crypto.createHash('md5')
      md5sum.update(os.hostname())
      this.savedHashedHostName = md5sum.digest('hex')
      return this.savedHashedHostName
    }
  },

  savedHashedPid: null,
  hashedPid: function () {
    if (this.savedHashedPid != null) {
      return this.savedHashedPid
    } else {
      var md5sum = crypto.createHash('md5')
      md5sum.update(String(process.pid))
      this.savedHashedPid = md5sum.digest('hex')
      return this.savedHashedPid
    }
  },

  parseCookies: function (req) {
    var cookies = {}
    if (req.headers.cookie != null) {
      req.headers.cookie.split(';').forEach(function (cookie) {
        var parts = cookie.split('=')
        cookies[ parts[ 0 ].trim() ] = (parts[ 1 ] || '').trim()
      })
    }
    return cookies
  },

  calculateHashFromElemets: function (elementsHash) {
    var shasum = crypto.createHash('sha1')
    for (var i in elementsHash) {
      shasum.update(elementsHash[i])
    }
    return shasum.digest('hex')
  },

  sortAndStringObject: function (o) {
    var sorted = {}
    var key
    var a = []

    for (key in o) {
      if (o.hasOwnProperty(key)) {
        a.push(key)
      }
    }
    a.sort()
    for (key = 0; key < a.length; key++) {
      sorted[a[key]] = String(o[a[key]])
    }
    return sorted
  }

}

module.exports = browserFingerprint
