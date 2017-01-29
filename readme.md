# Browser Fingerprint

[![Build Status](https://travis-ci.org/evantahler/browser_fingerprint.svg?branch=master)](https://travis-ci.org/evantahler/browser_fingerprint)

This module attempts to uniquely identify browsers by examining their header and connection information.  This information can be used as a "poor-man's" session identifier in your node projects. This module can optionally set a cookie to 'lock' in a consistent fingerprint.

Resuming sessions require that either the cookie be returned to the server, or a x-header `x-__browserFingerprint` in the default case, be sent on subsequent requests

```javascript
	var http = require('http');
	var browserFingerprint = require('browser_fingerprint');

	// these are the default options
	var options = {
		cookieKey: "__browserFingerprint",  // The name of the cookie we'll save to identify this browser on subsequent requests
		toSetCookie: true,                  // Should we set a cookie?
		onlyStaticElements: false,          // Should we only use components to our hash algorithm which can be deterministically recreated, or are random elements allowed?
		settings: {
	    path: '/',                        // cooke path (use `/` for this whole domain)
	    expires: 3600000,                 // cookie expiry
	  }
	};

	http.createServer(function (req, res) {
		browserFingerprint.fingerprint(req, options, function(error, fingerprint, elementHash, cookieHash){
			if (error) { throw error }

			cookieHash['Content-Type'] = 'text/plain' // append any other headers you want
			res.writeHead(200, cookieHash);

			var resp = "";
			resp += 'Your Browser Fingerprint: ' + fingerprint + "\r\n\r\n";
			for(var i in elementHash){
				resp += "Element " + i + ": " + elementHash[i] + "\r\n";
			}

			res.end(resp);

			console.log('request from ' + req.connection.remoteAddress + ', fingerprint -> ' + fingerprint);
		});
	}).listen(8080, '127.0.0.1');

	console.log('Server running at http://127.0.0.1:8080/' + '\r\n');
```
