import { execFileSync } from "node:child_process";
import {
  existsSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const START_MARKER = "<!-- vnts-downloads:start -->";
const END_MARKER = "<!-- vnts-downloads:end -->";

const TARGETS = [
  ["Windows", "x86_64", "x86_64-pc-windows-msvc"],
  ["Windows", "x86", "i686-pc-windows-msvc"],
  ["Windows", "ARM64", "aarch64-pc-windows-msvc"],
  ["Linux", "x86_64", "x86_64-unknown-linux-musl"],
  ["Linux", "ARM64", "aarch64-unknown-linux-musl"],
  ["Linux", "ARMv7 hard-float", "armv7-unknown-linux-musleabihf"],
  ["Linux", "ARMv7 soft-float", "armv7-unknown-linux-musleabi"],
  ["Linux", "ARM hard-float", "arm-unknown-linux-musleabihf"],
  ["Linux", "ARM soft-float", "arm-unknown-linux-musleabi"],
  ["Linux", "MIPS little-endian", "mipsel-unknown-linux-musl"],
  ["Linux", "MIPS big-endian", "mips-unknown-linux-musl"],
  ["macOS", "Apple Silicon", "aarch64-apple-darwin"],
  ["macOS", "Intel", "x86_64-apple-darwin"],
  ["FreeBSD", "x86_64", "x86_64-unknown-freebsd"],
];

function assetName(target, tag) {
  const extension = target.includes("windows") ? ".exe" : "";
  return `vnts2-${target}-${tag}${extension}`;
}

export function buildDownloadSection({ tag, releaseUrl, assetNames }) {
  const rows = TARGETS.flatMap(([platform, architecture, target]) => {
    const filename = assetName(target, tag);
    if (!assetNames.has(filename)) return [];

    const url = `${releaseUrl}/${encodeURIComponent(filename)}`;
    return [`| VNTS 服务端 | ${platform} | ${architecture} | [下载](${url}) |`];
  });

  if (rows.length === 0) return undefined;

  return [
    START_MARKER,
    "## 下载",
    "",
    "| 产品 | 平台 | 架构 | 下载 |",
    "|---|---|---|---|",
    ...rows,
    END_MARKER,
  ].join("\n");
}

export function mergeDownloadSection(notes, section) {
  const start = notes.indexOf(START_MARKER);
  if (start === -1) {
    const existing = notes.trimEnd();
    return existing.length === 0 ? `${section}\n` : `${existing}\n\n${section}\n`;
  }

  const end = notes.indexOf(END_MARKER, start);
  if (end === -1) {
    throw new Error("release notes contain an incomplete download section");
  }

  return `${notes.slice(0, start)}${section}${notes.slice(end + END_MARKER.length)}`;
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function main() {
  const repository = requiredEnv("GITHUB_REPOSITORY");
  const tag = requiredEnv("GITHUB_REF_NAME");
  const serverUrl = requiredEnv("GITHUB_SERVER_URL").replace(/\/$/, "");
  const release = JSON.parse(
    execFileSync("gh", ["api", `repos/${repository}/releases/tags/${tag}`], {
      encoding: "utf8",
      env: process.env,
      windowsHide: true,
    }),
  );

  const releaseUrl = `${serverUrl}/${repository}/releases/download/${tag}`;
  const assetNames = new Set(release.assets.map((asset) => asset.name));
  const section = buildDownloadSection({ tag, releaseUrl, assetNames });
  if (!section) throw new Error(`release ${tag} does not contain recognized assets`);

  const notes = release.body || "";
  const updatedNotes = mergeDownloadSection(notes, section);
  if (updatedNotes === notes) return;

  const notesFile = join(
    process.env.RUNNER_TEMP || tmpdir(),
    `vnts-release-notes-${process.pid}.md`,
  );
  try {
    writeFileSync(notesFile, updatedNotes);
    execFileSync(
      "gh",
      ["release", "edit", tag, "--repo", repository, "--notes-file", notesFile],
      { stdio: "inherit", env: process.env, windowsHide: true },
    );
  } finally {
    if (existsSync(notesFile)) unlinkSync(notesFile);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
