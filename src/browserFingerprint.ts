import { IncomingMessage } from "http";
import * as crypto from "crypto";
import * as os from "os";

export class BrowserFingerprint {
  options: {
    cookieKey?: string;
    toSetCookie?: boolean;
    onlyStaticElements?: boolean;
    settings?: { [key: string]: any };
  };
  savedHashedHostName: string;
  savedHashedPid: number | string;

  constructor(options = {}) {
    this.options = options;
    this.savedHashedHostName = null;
    this.savedHashedPid = null;

    this.hashedHostName();
    this.hashedPid();
  }

  /**
   * The goal is to come up with as many *potentially* unique traits for the connection and add them to the elementsHash.
   * The collection of all the elementsHash keys will *hopefully* be unique enough for fingerprinting
   * Then, we save this hash in a cookie for later retrieval
   */
  fingerprint(req: IncomingMessage): {
    fingerprint: string;
    headersHash: Record<string, string>;
    elementsHash: Record<string, string | number>;
  } {
    let fingerprint: string;
    let key: string;
    let value: string;
    let headersHash: Record<string, string> = {};
    let elementsHash: Record<string, string | number> = {
      clientCookie: fingerprint,
    };
    const cookies = this.parseCookies(req);

    // set defaults
    this.options.cookieKey = this.options.cookieKey ?? "__browser_fingerprint";
    this.options.toSetCookie = this.options.toSetCookie ?? true;
    this.options.onlyStaticElements = this.options.onlyStaticElements ?? false;

    // early returns
    if (cookies[this.options.cookieKey] != null) {
      fingerprint = cookies[this.options.cookieKey];
      return { fingerprint, elementsHash, headersHash };
    }

    if (req.headers[this.options.cookieKey] != null) {
      fingerprint = req.headers[this.options.cookieKey] as string;
      return { fingerprint, elementsHash, headersHash };
    }

    if (req.headers[("x-" + this.options.cookieKey).toLowerCase()] != null) {
      fingerprint = req.headers[
        ("x-" + this.options.cookieKey).toLowerCase()
      ] as string;
      return { fingerprint, elementsHash, headersHash };
    }

    let remoteAddress = req.headers["x-forwarded-for"];
    if (!remoteAddress) {
      remoteAddress = req.connection.remoteAddress;
    }

    elementsHash = {
      httpVersion: req.httpVersion,
      remoteAddress: remoteAddress as string,
      cookieKey: this.options.cookieKey,
      hashedHostName: this.hashedHostName(),
      remotePort: undefined as number,
      rand: undefined as number,
      time: undefined as number,
      hashedPid: undefined as string | number,
    };

    // these elements add greater entropy to the fingerprint, but aren't guaranteed to be the same upon each request
    if (this.options.onlyStaticElements !== true) {
      elementsHash.remotePort = req.connection.remotePort;
      elementsHash.rand = Math.random();
      elementsHash.time = new Date().getTime();
      elementsHash.hashedPid = this.hashedPid();
    }

    for (const j in req.headers) {
      if (
        this.options.onlyStaticElements &&
        (j === "cookie" || j === "referer")
      ) {
        continue;
      }
      key = "header_" + j;
      elementsHash[key] = String(req.headers[j]);
    }

    //@ts-ignore
    elementsHash = this.sortAndStringObject(elementsHash);
    fingerprint = this.calculateHashFromElements(elementsHash);

    if (this.options.toSetCookie === true) {
      if (
        this.options.settings !== undefined &&
        this.options.settings !== null
      ) {
        let settingsParams = "";
        /*
        new version in object format e.g.
        settings : {path : '/', expires : 86400000 }

        old version till v0.0.4 e.g.
        settings :'path=/;expires=' + new Date(new Date().getTime() + 86400000).toUTCString()+';'
        */

        /* Check to be compatible to both version */
        if (typeof this.options.settings === "object") {
          for (key in this.options.settings) {
            if (
              Object.prototype.hasOwnProperty.call(this.options.settings, key)
            ) {
              value = this.options.settings[key];
              if (key === "expires") {
                value = new Date(
                  new Date().getTime() + this.options.settings[key]
                ).toUTCString();
              }
              settingsParams =
                settingsParams + key + (value ? "=" + value : "") + ";";
            }
          }
        } else {
          settingsParams = this.options.settings;
        }
        headersHash = {
          "Set-Cookie":
            this.options.cookieKey + "=" + fingerprint + ";" + settingsParams,
        };
      } else {
        headersHash = {
          "Set-Cookie": this.options.cookieKey + "=" + fingerprint,
        };
      }
    }

    return { fingerprint, elementsHash, headersHash };
  }

  hashedHostName() {
    if (this.savedHashedHostName != null) {
      return this.savedHashedHostName;
    } else {
      const md5sum = crypto.createHash("md5");
      md5sum.update(os.hostname());
      this.savedHashedHostName = md5sum.digest("hex");
      return this.savedHashedHostName;
    }
  }

  hashedPid() {
    if (this.savedHashedPid != null) {
      return this.savedHashedPid;
    } else {
      const md5sum = crypto.createHash("md5");
      md5sum.update(String(process.pid));
      this.savedHashedPid = md5sum.digest("hex");
      return this.savedHashedPid;
    }
  }

  parseCookies(req: IncomingMessage) {
    const cookies: Record<string, string> = {};
    if (req.headers.cookie != null) {
      req.headers.cookie.split(";").forEach((cookie: string) => {
        const parts = cookie.split("=");
        cookies[parts[0].trim()] = (parts[1] || "").trim();
      });
    }

    return cookies;
  }

  calculateHashFromElements(elementsHash: Record<string, string | number>) {
    const shaSum = crypto.createHash("sha1");
    for (const i in elementsHash) shaSum.update(String(elementsHash[i]));
    return shaSum.digest("hex");
  }

  sortAndStringObject(o: { [key: string]: any }) {
    const sorted: { [key: string]: any } = {};
    var key;
    const a = [];

    for (key in o) {
      if (Object.prototype.hasOwnProperty.call(o, key)) {
        a.push(key);
      }
    }

    a.sort();

    for (key = 0; key < a.length; key++) {
      sorted[a[key]] = String(o[a[key]]);
    }

    return sorted;
  }
}
