import assert from "node:assert/strict";
import test from "node:test";

import {
  buildDownloadSection,
  mergeDownloadSection,
} from "./update-release-downloads.mjs";

test("builds links only for published VNTS binaries", () => {
  const section = buildDownloadSection({
    tag: "v2.0.3",
    releaseUrl: "https://github.com/vnt-dev/vnts/releases/download/v2.0.3",
    assetNames: new Set([
      "vnts2-x86_64-pc-windows-msvc-v2.0.3.exe",
      "vnts2-aarch64-unknown-linux-musl-v2.0.3",
    ]),
  });

  assert.match(section, /vnts2-x86_64-pc-windows-msvc-v2\.0\.3\.exe/);
  assert.match(section, /vnts2-aarch64-unknown-linux-musl-v2\.0\.3/);
  assert.doesNotMatch(section, /vnts2-mips-unknown-linux-musl-v2\.0\.3/);
});

test("replaces an existing download section", () => {
  const oldSection = [
    "<!-- vnts-downloads:start -->",
    "old links",
    "<!-- vnts-downloads:end -->",
  ].join("\n");

  const merged = mergeDownloadSection(`Release notes\n\n${oldSection}\n`, "new links");

  assert.equal(merged, "Release notes\n\nnew links\n");
});
