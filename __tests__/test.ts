import * as path from "path";
import * as http from "http";
import * as request from "request-promise-native";
import { BrowserFingerprint } from "./../src/browserFingerprint";

const port = 8081;
const url = `http://localhost:${port}`;

let fingerPrinter = new BrowserFingerprint();

let server;
let fingerprint;

describe("browser fingerpint", () => {
  beforeAll(() => {
    server = http
      .createServer((req, res) => {
        const {
          fingerprint,
          elementHash,
          headersHash,
        } = fingerPrinter.fingerprint(req);
        headersHash["Content-Type"] = "text/plain";
        res.writeHead(200, headersHash);
        let resp = `Fingerprint: ${fingerprint} \r\n\r\n`;
        for (const i in elementHash) {
          resp += `Element ${i}: ${elementHash[i]}\r\n`;
        }
        res.end(resp);
      })
      .listen(port);
  });

  afterAll(() => {
    server.close();
  });

  it("works with defaults", async () => {
    const { body, headers } = await request.get(url, {
      resolveWithFullResponse: true,
    });

    const fingerprintCookie = headers["set-cookie"][0];
    fingerprint = fingerprintCookie.split("=")[1];
    expect(body).toContain(fingerprint);
  });

  it("will generate a new fingerprint for a new request", async () => {
    const { body, headers } = await request.get(url, {
      resolveWithFullResponse: true,
    });

    const fingerprintCookie = headers["set-cookie"][0];
    const thisFingerprint = fingerprintCookie.split("=")[1];
    expect(thisFingerprint).not.toBe(fingerprint);
  });

  it("can have a custom cookieKey", async () => {
    const { body, headers } = await request.get(url, {
      resolveWithFullResponse: true,
    });

    const fingerprintCookie = headers["set-cookie"][0];
    const cookieKey = fingerprintCookie.split("=")[0];
    expect(cookieKey).not.toBe("myCookie");
  });

  it("can have more entropy", async () => {
    const { body, headers } = await request.get(url, {
      resolveWithFullResponse: true,
    });

    const fingerprintCookie = headers["set-cookie"][0];
    const thisFingerprint = fingerprintCookie.split("=")[1];
    expect(thisFingerprint).not.toBe(fingerprint);
  });

  it("will return the same fingerprint if the cookie is already set via cookie, and not re-set the cookie", async () => {
    const jar = request.jar();

    const { body, headers } = await request.get(url, {
      jar,
      resolveWithFullResponse: true,
    });

    const fingerprintCookie = headers["set-cookie"][0];
    const thisFingerprint = fingerprintCookie.split("=")[1];
    expect(body).toContain(thisFingerprint);

    const secondResponse = await request.get(url, {
      jar,
      resolveWithFullResponse: true,
    });

    expect(secondResponse.headers["set-cookie"]).toBeUndefined();
    expect(secondResponse.body).toContain(thisFingerprint);
  });

  it("will return the same fingerprint if the cookie is already set via header, and not re-set the cookie", async () => {
    const { body, headers } = await request.get(url, {
      resolveWithFullResponse: true,
    });

    const fingerprintCookie = headers["set-cookie"][0];
    const thisFingerprint = fingerprintCookie.split("=")[1];
    expect(body).toContain(thisFingerprint);

    const secondResponse = await request.get(url, {
      headers: {
        __browser_fingerprint: thisFingerprint,
      },
      resolveWithFullResponse: true,
    });

    expect(secondResponse.headers["set-cookie"]).toBeUndefined();
    expect(secondResponse.body).toContain(thisFingerprint);
  });

  it("will return the same fingerprint if the cookie is already set via x-header, and not re-set the cookie", async () => {
    const { body, headers } = await request.get(url, {
      resolveWithFullResponse: true,
    });

    const fingerprintCookie = headers["set-cookie"][0];
    const thisFingerprint = fingerprintCookie.split("=")[1];
    expect(body).toContain(thisFingerprint);

    const secondResponse = await request.get(url, {
      headers: {
        "x-__browser_fingerprint": thisFingerprint,
      },
      resolveWithFullResponse: true,
    });

    expect(secondResponse.headers["set-cookie"]).toBeUndefined();
    expect(secondResponse.body).toContain(thisFingerprint);
  });

  it("can disable setting the cookie", async () => {
    fingerPrinter = new BrowserFingerprint({ toSetCookie: false });

    const { body, headers } = await request.get(url, {
      resolveWithFullResponse: true,
    });

    expect(headers["set-cookie"]).toBeUndefined();
  });

  it("works with directives without value", async () => {
    const options = { settings: { httpOnly: null, secure: null } };
    fingerPrinter = new BrowserFingerprint(options);

    const { body, headers } = await request.get(url, {
      resolveWithFullResponse: true,
    });

    const fingerprintCookie = headers["set-cookie"][0];
    const httpOnlyDirective = fingerprintCookie.split(";")[1];
    const secureDirective = fingerprintCookie.split(";")[2];

    expect(httpOnlyDirective).toBe("httpOnly");
    expect(secureDirective).toBe("secure");
  });

  it("works with directives with and without value", async () => {
    const options = {
      settings: { expires: 3600000, httpOnly: null, path: "/", secure: null },
    };
    fingerPrinter = new BrowserFingerprint(options);

    const { body, headers } = await request.get(url, {
      resolveWithFullResponse: true,
    });

    const fingerprintCookie = headers["set-cookie"][0];
    const expiresDirective = fingerprintCookie.split(";")[1];
    const httpOnlyDirective = fingerprintCookie.split(";")[2];
    const pathDirective = fingerprintCookie.split(";")[3];
    const secureDirective = fingerprintCookie.split(";")[4];

    expect(expiresDirective).toContain("expires=");
    expect(httpOnlyDirective).toBe("httpOnly");
    expect(secureDirective).toBe("secure");
    expect(pathDirective).toBe("path=/");
  });
});
