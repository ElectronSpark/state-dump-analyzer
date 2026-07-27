import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
} from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const frontendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(frontendRoot, "..");
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

function walkFiles(root) {
  if (!existsSync(root)) return [];
  const files = [];
  const pending = [root];
  while (pending.length) {
    const current = pending.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const candidate = join(current, entry.name);
      if (entry.isDirectory()) {
        pending.push(candidate);
      } else if (entry.isFile()) {
        files.push(candidate);
      }
    }
  }
  return files;
}

function resolveAssetReference(reference, importer) {
  const lexicalPath = resolve(dirname(importer), reference);
  if (
    lexicalPath !== assetsDirectory &&
    !lexicalPath.startsWith(`${assetsDirectory}${sep}`)
  ) {
    fail(`${importer} imports an asset outside assets/: ${reference}`);
  }
  if (!existsSync(lexicalPath)) {
    fail(`${importer} imports missing asset ${reference}`);
  }
  const realPath = realpathSync(lexicalPath);
  if (!realPath.startsWith(`${assetsDirectory}${sep}`)) {
    fail(`${importer} imports an asset resolving outside assets/: ${reference}`);
  }
  return realPath;
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

const declaredPages = new Set();
const referencedAssets = new Set();
const checkedScripts = new Set();
for (const [route, pageRelative] of Object.entries(manifest.pages)) {
  const pagePath = resolveInside(pageRelative, `pages[${route}]`);
  if (!statSync(pagePath).isFile()) {
    fail(`page does not exist: ${pagePath}`);
  }
  declaredPages.add(pagePath);
  const html = readFileSync(pagePath, "utf8");
  const references = html.matchAll(/(?:href|src)=["'](\/assets\/[^"'?#]+)(?:[?#][^"']*)?["']/g);
  for (const match of references) {
    const relativeAsset = match[1].slice("/assets/".length);
    const assetPath = resolveAssetReference(relativeAsset, join(assetsDirectory, "_page.html"));
    referencedAssets.add(assetPath);
    if (assetPath.endsWith(".js")) {
      checkedScripts.add(assetPath);
    }
  }
}

// Follow the local module graph so shared modules are validated and counted as
// reachable assets instead of becoming a second, untracked entry point.
const scriptQueue = [...checkedScripts];
for (let index = 0; index < scriptQueue.length; index += 1) {
  const scriptPath = scriptQueue[index];
  const source = readFileSync(scriptPath, "utf8");
  const moduleReferences = source.matchAll(
    /(?:^|\n)\s*(?:import|export)\s+(?:[^"'`;]*?\s+from\s+)?["']([^"']+)["']/g,
  );
  for (const match of moduleReferences) {
    if (!match[1].startsWith(".")) {
      fail(`${scriptPath} uses an unbundled module specifier: ${match[1]}`);
    }
    const dependency = resolveAssetReference(match[1], scriptPath);
    if (!dependency.endsWith(".js")) {
      fail(`${scriptPath} imports a non-JavaScript asset: ${match[1]}`);
    }
    referencedAssets.add(dependency);
    if (!checkedScripts.has(dependency)) {
      checkedScripts.add(dependency);
      scriptQueue.push(dependency);
    }
  }
}

for (const scriptPath of scriptQueue) {
  const result = spawnSync(process.execPath, ["--check", scriptPath], {
    encoding: "utf8",
  });
  if (result.status !== 0) {
    fail(result.stderr || `JavaScript syntax check failed: ${scriptPath}`);
  }
}

const browserPages = walkFiles(frontendRoot)
  .filter((path) => path.endsWith(".html"));
const browserAssets = walkFiles(assetsDirectory)
  .filter((path) => path.endsWith(".css") || path.endsWith(".js"))
  .map((path) => realpathSync(path));
const undeclaredPages = browserPages.filter(
  (path) => !declaredPages.has(realpathSync(path)),
);
const unreachableAssets = browserAssets.filter(
  (path) => !referencedAssets.has(path),
);
if (undeclaredPages.length || unreachableAssets.length) {
  fail(
    "frontend contains files unreachable from its manifest: " +
      [...undeclaredPages, ...unreachableAssets].join(", "),
  );
}

const hashes = new Map();
for (const filePath of [...browserPages, ...browserAssets]) {
  const extension = filePath.slice(filePath.lastIndexOf("."));
  const digest = createHash("sha256")
    .update(readFileSync(filePath))
    .digest("hex");
  const key = `${extension}:${digest}`;
  if (hashes.has(key)) {
    fail(`duplicate executable frontend files: ${hashes.get(key)} and ${filePath}`);
  }
  hashes.set(key, filePath);
}

const sourceRoots = [
  frontendRoot,
  resolve(repositoryRoot, "src"),
  resolve(repositoryRoot, "demo"),
  resolve(repositoryRoot, "scripts"),
];
const sourceFiles = sourceRoots.flatMap(walkFiles);
const sourceManifests = sourceFiles.filter(
  (path) => path.endsWith(`${sep}frontend-manifest.json`),
);
if (
  sourceManifests.length !== 1 ||
  realpathSync(sourceManifests[0]) !== realpathSync(manifestPath)
) {
  fail(
    "repository must contain exactly one source frontend distribution: " +
      sourceManifests.join(", "),
  );
}
const duplicateBrowserSources = sourceFiles.filter((path) => (
  !realpathSync(path).startsWith(`${realFrontendRoot}${sep}`) &&
  (path.endsWith(".html") || path.endsWith(".css") || path.endsWith(".js"))
));
if (duplicateBrowserSources.length) {
  fail(
    "browser assets/templates remain outside core frontend/: " +
      duplicateBrowserSources.join(", "),
  );
}

process.stdout.write(
  `Frontend contract valid: ${Object.keys(manifest.pages).length} routes, ` +
    `${checkedScripts.size} JavaScript modules, one source distribution.\n`,
);
