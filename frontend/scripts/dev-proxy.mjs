import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

const readMethods = new Set(["GET", "HEAD", "OPTIONS"]);

export function frontendOrigin(host, port) {
  if (["", "0.0.0.0", "::", "[::]"].includes(host)) return null;
  const authority = host.includes(":") && !host.startsWith("[")
    ? `[${host}]:${port}`
    : `${host}:${port}`;
  return new URL(`http://${authority}`).origin;
}

function headerValues(incoming, name) {
  const values = [];
  for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
    if (incoming.rawHeaders[index].toLowerCase() === name) {
      values.push(incoming.rawHeaders[index + 1]);
    }
  }
  return values;
}

function sendText(response, statusCode, message) {
  response.writeHead(statusCode, {
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(message);
}

export function createDevProxy({ backend, origin }) {
  const backendUrl = new URL(backend);
  const frontendHost = origin === null ? null : new URL(origin).host;
  if (!["http:", "https:"].includes(backendUrl.protocol)) {
    throw new Error("--backend must use http:// or https://");
  }
  return function proxyRequest(incoming, response) {
    const headers = { ...incoming.headers };
    const hosts = headerValues(incoming, "host");
    // Rewriting Host must not bypass the backend's DNS-rebinding protection,
    // including reads and non-browser requests without an Origin header.
    if (frontendHost !== null && (hosts.length !== 1 || hosts[0] !== frontendHost)) {
      sendText(response, 403, "Request host is not allowed\n");
      return;
    }
    if (!readMethods.has(incoming.method)) {
      const origins = headerValues(incoming, "origin");
      if (origins.length !== 0) {
        if (
          origin === null || origins.length !== 1 || origins[0] !== origin ||
          hosts.length !== 1 || hosts[0] !== frontendHost
        ) {
          sendText(response, 403, "Request origin is not allowed\n");
          return;
        }
        headers.origin = backendUrl.origin;
      }
    }
    const requested = new URL(incoming.url, "http://frontend.invalid");
    const target = new URL(backendUrl);
    target.pathname = requested.pathname;
    target.search = requested.search;
    headers.host = target.host;
    const transport = target.protocol === "https:" ? httpsRequest : httpRequest;
    const upstream = transport(
      target,
      { method: incoming.method, headers },
      (upstreamResponse) => {
        response.writeHead(
          upstreamResponse.statusCode ?? 502,
          upstreamResponse.headers,
        );
        upstreamResponse.pipe(response);
      },
    );
    upstream.on("error", (error) => {
      if (!response.headersSent) {
        sendText(response, 502, `Backend unavailable: ${error.message}\n`);
      } else {
        response.destroy(error);
      }
    });
    incoming.pipe(upstream);
  };
}
