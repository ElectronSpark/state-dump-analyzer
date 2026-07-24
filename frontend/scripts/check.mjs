import { spawnSync } from "node:child_process";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const frontendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const realFrontendRoot = realpathSync(frontendRoot);
const manifestPath = join(frontendRoot, "frontend-manifest.json");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));

function fail(message) {
  throw new Error(message);
}

function resolveInside(relativePath, label) {
  if (
    typeof relativePath !== "string" ||
    !relativePath ||
    relativePath.includes("\\") ||
    relativePath.split("/").includes("..")
  ) {
    fail(`${label} must be a POSIX-style path inside frontend/`);
  }
  const candidate = resolve(frontendRoot, relativePath);
  if (candidate !== frontendRoot && !candidate.startsWith(`${frontendRoot}${sep}`)) {
    fail(`${label} escapes frontend/`);
  }
  const realCandidate = realpathSync(candidate);
  if (
    realCandidate !== realFrontendRoot &&
    !realCandidate.startsWith(`${realFrontendRoot}${sep}`)
  ) {
    fail(`${label} resolves outside frontend/`);
  }
  return realCandidate;
}

if (manifest.schema_version !== 1) {
  fail("frontend manifest schema_version must equal 1");
}
for (const route of ["/", "/topology", "/node"]) {
  if (!manifest.pages?.[route]) {
    fail(`frontend manifest is missing ${route}`);
  }
}

const assetsPrefix = manifest.assets?.url_prefix;
const assetsDirectory = resolveInside(
  manifest.assets?.directory,
  "assets.directory",
);
if (assetsPrefix !== "/assets" || !statSync(assetsDirectory).isDirectory()) {
  fail("manifest assets must map /assets to an existing directory");
}

const checkedScripts = new Set();
for (const [route, pageRelative] of Object.entries(manifest.pages)) {
  const pagePath = resolveInside(pageRelative, `pages[${route}]`);
  if (!statSync(pagePath).isFile()) {
    fail(`page does not exist: ${pagePath}`);
  }
  const html = readFileSync(pagePath, "utf8");
  const references = html.matchAll(/(?:href|src)=["'](\/assets\/[^"'?#]+)(?:[?#][^"']*)?["']/g);
  for (const match of references) {
    const relativeAsset = match[1].slice("/assets/".length);
    const assetPath = realpathSync(resolve(assetsDirectory, relativeAsset));
    if (!assetPath.startsWith(`${assetsDirectory}${sep}`) || !statSync(assetPath).isFile()) {
      fail(`${route} references missing asset ${match[1]}`);
    }
    if (assetPath.endsWith(".js")) {
      checkedScripts.add(assetPath);
    }
  }
}

for (const scriptPath of checkedScripts) {
  const result = spawnSync(process.execPath, ["--check", scriptPath], {
    encoding: "utf8",
  });
  if (result.status !== 0) {
    fail(result.stderr || `JavaScript syntax check failed: ${scriptPath}`);
  }
}

process.stdout.write(
  `Frontend contract valid: ${Object.keys(manifest.pages).length} routes, ` +
    `${checkedScripts.size} JavaScript entry points.\n`,
);
