#!/usr/bin/env node

var http = require('http')
// var bf = require('browser_fingerprint'); <<-- Normally, you would do this
var browserFingerprint = require('../lib/browser_fingerprint.js')

// these are the default options
var options = {
  cookieKey: '__browser_fingerprint',
  toSetCookie: true,
  onlyStaticElements: true,
  settings: {
    path: '/',
    expires: 3600000
  }
}

http.createServer(function (req, res) {
  browserFingerprint.fingerprint(req, options, function (error, fingerprint, elementHash, cookieHash) {
    if (error) { throw error }
    cookieHash['Content-Type'] = 'text/plain' // append any other headers you want
    res.writeHead(200, cookieHash)

    var resp = ''
    resp += 'Your Browser Fingerprint: ' + fingerprint + '\r\n\r\n'
    for (var i in elementHash) {
      resp += 'Element ' + i + ': ' + elementHash[i] + '\r\n'
    }

    res.end(resp)

    console.log('requset from ' + req.connection.remoteAddress + ', fingerprint -> ' + fingerprint)
  })
}).listen(8080)

console.log('Server running at http://127.0.0.1:8080/' + '\r\n')
