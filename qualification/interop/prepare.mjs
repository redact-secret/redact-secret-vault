import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync, existsSync, readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";

export const revisions = Object.freeze({
  anonymizer: "e6864ee05248b8c83d1e7484e84e8b1cde27ed67",
  restore: "e9c4863bf887956d004438d0229d04a9a85667dc",
});
const root = resolve(import.meta.dirname, "../..");
for (const [name, revision] of Object.entries(revisions)) {
  const directory = resolve(root, ".qualification/interop/siblings", name);
  const marker = resolve(directory, ".interop-revision");
  if (existsSync(marker) && readFileSync(marker, "utf8").trim() === revision) continue;
  // A stale checkout is not evidence for the pinned revision.
  rmSync(directory, { recursive: true, force: true });
  const response = await fetch(`https://api.github.com/repos/redact-secret/${name}/tarball/${revision}`, { headers: { Accept: "application/vnd.github+json" } });
  if (!response.ok) throw new Error(`Pinned sibling download failed: ${name}`);
  const archive = resolve(root, ".qualification/interop", `${name}-${revision}.tar.gz`);
  mkdirSync(directory, { recursive: true });
  writeFileSync(archive, new Uint8Array(await response.arrayBuffer()));
  execFileSync("tar", ["-xzf", archive, "--strip-components=1", "-C", directory], { stdio: "ignore" });
  writeFileSync(marker, revision);
}
execFileSync("cargo", ["build", "--locked", "--manifest-path", "qualification/interop/rust/Cargo.toml", "--target-dir", ".qualification/interop/target"], { cwd: root, stdio: "inherit" });
