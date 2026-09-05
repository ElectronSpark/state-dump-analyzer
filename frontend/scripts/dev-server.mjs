import {
  createReadStream,
  readFileSync,
  realpathSync,
  statSync,
} from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createDevProxy, frontendOrigin } from "./dev-proxy.mjs";

const frontendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const realFrontendRoot = realpathSync(frontendRoot);
const manifest = JSON.parse(
  readFileSync(resolve(frontendRoot, "frontend-manifest.json"), "utf8"),
);

const options = {
  host: "127.0.0.1",
  port: 4173,
  backend: "http://127.0.0.1:8765",
};
for (let index = 2; index < process.argv.length; index += 1) {
  const name = process.argv[index];
  const value = process.argv[index + 1];
  if (!["--host", "--port", "--backend"].includes(name) || value === undefined) {
    throw new Error(`Unknown or incomplete option: ${name}`);
  }
  options[name.slice(2)] = name === "--port" ? Number(value) : value;
  index += 1;
}
if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
  throw new Error("--port must be an integer from 1 through 65535");
}

const backend = new URL(options.backend);
if (!["http:", "https:"].includes(backend.protocol)) {
  throw new Error("--backend must use http:// or https://");
}
const assetsDirectory = realpathSync(
  resolve(frontendRoot, manifest.assets.directory),
);
if (!assetsDirectory.startsWith(`${realFrontendRoot}${sep}`)) {
  throw new Error("Manifest asset directory resolves outside frontend/");
}
const proxyPrefixes = manifest.development?.backend_proxy_prefixes ?? [];
const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".map", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
]);

function sendText(response, statusCode, message) {
  response.writeHead(statusCode, {
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(message);
}

const proxyRequest = createDevProxy({
  backend,
  origin: frontendOrigin(options.host, options.port),
});

function safeAssetPath(pathname) {
  const encodedRelative = pathname.slice(`${manifest.assets.url_prefix}/`.length);
  let relative;
  try {
    relative = decodeURIComponent(encodedRelative);
  } catch {
    return null;
  }
  if (!relative || relative.includes("\0")) {
    return null;
  }
  const candidate = resolve(assetsDirectory, relative);
  if (!candidate.startsWith(`${assetsDirectory}${sep}`)) {
    return null;
  }
  try {
    const realCandidate = realpathSync(candidate);
    return realCandidate.startsWith(`${assetsDirectory}${sep}`)
      ? realCandidate
      : null;
  } catch {
    return null;
  }
}

function safePagePath(relative) {
  const candidate = resolve(frontendRoot, relative);
  if (
    candidate !== frontendRoot &&
    !candidate.startsWith(`${frontendRoot}${sep}`)
  ) {
    return null;
  }
  try {
    const realCandidate = realpathSync(candidate);
    return realCandidate.startsWith(`${realFrontendRoot}${sep}`)
      ? realCandidate
      : null;
  } catch {
    return null;
  }
}

const server = createServer((request, response) => {
  const requestUrl = new URL(request.url, "http://frontend.invalid");
  const pathname = requestUrl.pathname;
  if (
    proxyPrefixes.some(
      (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
    )
  ) {
    proxyRequest(request, response);
    return;
  }
  if (!["GET", "HEAD"].includes(request.method ?? "")) {
    sendText(response, 405, "Method not allowed\n");
    return;
  }

  let filePath = null;
  if (manifest.pages[pathname]) {
    filePath = safePagePath(manifest.pages[pathname]);
  } else if (pathname.startsWith(`${manifest.assets.url_prefix}/`)) {
    filePath = safeAssetPath(pathname);
  }
  if (filePath === null) {
    sendText(response, 404, "Not found\n");
    return;
  }
  try {
    if (!statSync(filePath).isFile()) {
      sendText(response, 404, "Not found\n");
      return;
    }
  } catch {
    sendText(response, 404, "Not found\n");
    return;
  }

  response.writeHead(200, {
    "content-type": contentTypes.get(extname(filePath)) ?? "application/octet-stream",
    "cache-control": "no-store, no-cache, must-revalidate, max-age=0",
  });
  if (request.method === "HEAD") {
    response.end();
    return;
  }
  createReadStream(filePath).pipe(response);
});

server.listen(options.port, options.host, () => {
  process.stdout.write(
    `Router State Lab frontend: http://${options.host}:${options.port}\n` +
      `Proxying API requests to ${backend.origin}\n`,
  );
});
