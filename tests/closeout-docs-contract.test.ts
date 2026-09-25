import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();
const SCHEME_PATH = "/home/tiezbro/projects/MAACS/docs/maacs-paseo-agy-acp-confirmed-scheme.md";
const OLD_DESIGN_PATH = "docs/design/v2.0.0.0-admission-controller.md";

const STAGE2_ARTIFACTS = [
  "docs/design/v2.0.0.0-stage2-handoff.md",
  "docs/design/v2.0.0.0-stage2-503-feasibility.md",
  "docs/design/v2.0.0.0-stage2-acp-source-map.md",
  "docs/design/v2.0.0.0-stage2-admission-source-map.md",
  "docs/design/v2.0.0.0-stage2-architecture.md",
  "docs/design/v2.0.0.0-stage2-domain-model.md",
  "docs/design/v2.0.0.0-stage2-test-contracts.md",
  "docs/design/v2.0.0.0-stage2-spec.md"
];

function readDoc(relativePath: string): string {
  return readFileSync(path.join(ROOT, relativePath), "utf8");
}

function markdownTargets(markdown: string): string[] {
  return [...markdown.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)].map((match) => match[1]);
}

function executableBlocks(markdown: string): Array<{ language: string; body: string }> {
  return [...markdown.matchAll(/```(bash|json)\n([\s\S]*?)```/g)].map((match) => ({
    language: match[1],
    body: match[2]
  }));
}

describe("v2.0.0.0 closeout documentation contract", () => {
  it("keeps product READMEs current, bilingual, and separate from release history", () => {
    const failures: string[] = [];
    const requiredSections = [
      "positioning",
      "value",
      "architecture",
      "requirements",
      "quickstart",
      "configuration",
      "operations",
      "development",
      "license"
    ];
    const requiredTargets = [
      "./README.md",
      "./README.zh-CN.md",
      "./CHANGELOG.md",
      "docs/operations/admission.md",
      "docs/operations/admission.zh-CN.md",
      "docs/operations/official-kernel-compat-runbook.md",
      "docs/operations/npm-publishing.md"
    ];

    const readmes = [
      [
        "README.md",
        readDoc("README.md"),
        "Admission is supported on Linux and macOS `arm64` and `x64` hosts.",
        /Admission\s+remains disabled by default[.;]/,
        "Linux-only official-kernel compatibility lifecycle"
      ],
      [
        "README.zh-CN.md",
        readDoc("README.zh-CN.md"),
        "Admission 支持 Linux，以及 macOS `arm64` 和 `x64` 主机。",
        /Admission\s+默认保持禁用[。；]/,
        "仅限 Linux 的官方内核兼容生命周期"
      ]
    ] as const;

    for (const [label, contents, supportedPlatforms, defaultDisabled, compatibilityLifecycle] of readmes) {
      const links = markdownTargets(contents);
      for (const target of requiredTargets) {
        if (!links.includes(target)) {
          failures.push(`${label} does not link current target ${target}`);
        }
      }
      for (const section of requiredSections) {
        if (!contents.includes(`<!-- readme:${section} -->`)) {
          failures.push(`${label} lacks bilingual section marker ${section}`);
        }
      }
      for (const historicalTarget of [SCHEME_PATH, OLD_DESIGN_PATH, ...STAGE2_ARTIFACTS]) {
        if (links.includes(historicalTarget)) {
          failures.push(`${label} links historical authority ${historicalTarget}`);
        }
      }
      if (/\/home\/tiezbro\//.test(contents)) {
        failures.push(`${label} contains a maintainer-local absolute path`);
      }
      for (const staleRequirement of [
        "Linux filesystem ownership and mode support when Admission is enabled",
        "启用 Admission 时，系统需支持 Linux 文件 owner 与 mode"
      ]) {
        if (contents.includes(staleRequirement)) {
          failures.push(`${label} keeps stale platform requirement ${staleRequirement}`);
        }
      }
      if (!contents.includes(supportedPlatforms)) {
        failures.push(`${label} does not state the supported Admission platforms and architectures`);
      }
      if (!defaultDisabled.test(contents)) {
        failures.push(`${label} does not preserve default-disabled Admission behavior`);
      }
      if (!contents.includes(compatibilityLifecycle)) {
        failures.push(`${label} does not keep the compatibility lifecycle Linux-specific`);
      }
      if (/\b2\.(?:0|1|2)(?:\.\d+){1,2}\b/.test(contents)) {
        failures.push(`${label} contains historical release narration`);
      }
      if (!/\[English\]\(\.\/README\.md\) \| \[中文\]\(\.\/README\.zh-CN\.md\) \| \[Changelog\]\(\.\/CHANGELOG\.md\)/.test(contents)) {
        failures.push(`${label} does not expose Changelog after the language links`);
      }

      const sectionOrder = [...contents.matchAll(/<!-- readme:([^ ]+) -->/g)].map(
        (match) => match[1]
      );
      if (JSON.stringify(sectionOrder) !== JSON.stringify(requiredSections)) {
        failures.push(`${label} section order differs from the bilingual contract`);
      }
    }

    const english = readmes[0][1];
    const chinese = readmes[1][1];
    if (JSON.stringify(markdownTargets(english)) !== JSON.stringify(markdownTargets(chinese))) {
      failures.push("English and Chinese README link targets differ");
    }

    if (JSON.stringify(executableBlocks(english)) !== JSON.stringify(executableBlocks(chinese))) {
      failures.push("English and Chinese README executable examples differ");
    }

    expect(failures).toEqual([]);
  });

  it("keeps bilingual macOS Admission operations guidance aligned and bounded", () => {
    const english = readDoc("docs/operations/admission.md");
    const chinese = readDoc("docs/operations/admission.zh-CN.md");
    const failures: string[] = [];

    if (JSON.stringify(executableBlocks(english)) !== JSON.stringify(executableBlocks(chinese))) {
      failures.push("English and Chinese Admission executable examples differ");
    }

    for (const requiredLiteral of [
      "Linux",
      "macOS",
      "arm64",
      "x64",
      "AGY_ACP_ADMISSION_ENABLED",
      "AGY_ACP_STATE_DIR",
      "PASEO_AGENT_ID",
      "official-kernel",
      "0700",
      "0600",
      "stat -c '%U %a %n'",
      "stat -f '%Su %Lp %N'",
      "sudo chown \"$(id -un)\"",
      "chmod 700",
      "prebuilds/darwin-arm64/darwin_process_evidence.node",
      "prebuilds/darwin-x64/darwin_process_evidence.node",
      "build/Release/",
      "npm run build:native",
      "npm run test:native:source",
      "cancelled",
      "recovery_required",
      "unverifiable"
    ]) {
      for (const [label, contents] of [["English guide", english], ["Chinese guide", chinese]] as const) {
        if (!contents.includes(requiredLiteral)) {
          failures.push(`${label} lacks Admission operations literal ${requiredLiteral}`);
        }
      }
    }

    const semanticPatterns = [
      [/Admission\s+remains disabled by default[.;]/, /Admission\s+默认保持禁用[。；]/],
      [/Linux and macOS.*`arm64` and `x64`/, /Linux.*macOS.*`arm64`.*`x64`/],
      [/fresh.*account state root/is, /全新.*账号状态根/is],
      [/host-local and platform-bound/i, /宿主机本地.*绑定平台/is],
      [/never copy[\s\S]*another machine/is, /不要[\s\S]*复制/],
      [/nested `official-kernel` ledger/i, /嵌套.*`official-kernel`.*ledger/is],
      [/nested[\s\S]*directory.*`0700`/is, /嵌套.*目录.*`0700`/is],
      [/state files.*`0600`/is, /状态文件.*`0600`/is],
      [/Discovery.*does not.*Admission ledger/is, /Discovery.*不会.*Admission ledger/is],
      [/--login.*does not.*Admission/is, /--login.*不会.*Admission/is],
      [/Other operating systems.*fail closed/is, /其他操作系统.*fail closed/is],
      [/Policy mismatch/, /Policy mismatch/],
      [/Malformed.*evidence.*fail closed/is, /损坏.*证据.*fail closed/is],
      [/Queued-owner cancellation/, /queued-owner.*取消|排队 owner.*取消/is],
      [/Local seat release/, /本机.*席位.*释放/is],
      [/No-replay guarantee/, /不重放.*保证|永不重放/is],
      [/source-build fallback/, /源码构建回退/],
      [/expected platform.*actual platform/is, /expected platform.*actual\s+platform/is]
    ] as const;

    for (const [englishPattern, chinesePattern] of semanticPatterns) {
      if (!englishPattern.test(english)) {
        failures.push(`English Admission guide lacks semantic pattern ${englishPattern}`);
      }
      if (!chinesePattern.test(chinese)) {
        failures.push(`Chinese Admission guide lacks semantic pattern ${chinesePattern}`);
      }
    }

    const compatibilityRunbook = readDoc("docs/operations/official-kernel-compat-runbook.md");
    if (!/This lifecycle is strictly Linux-only\b/i.test(compatibilityRunbook)) {
      failures.push("official-kernel compatibility runbook does not declare its Linux-only boundary");
    }
    if (!/separate from macOS Admission support/i.test(compatibilityRunbook)) {
      failures.push("official-kernel compatibility runbook does not separate its lifecycle from macOS Admission");
    }

    expect(failures).toEqual([]);
  });

  it("records the final v2 behavior and Stage 4 release validation without stale claims", () => {
    const changelog = readDoc("CHANGELOG.md");
    const failures: string[] = [];

    for (const stalePattern of [
      /\bschema v1\b/i,
      /\beight business tables\b/i,
      /Reset the Admission database contract to `shared-admission-queue` schema v1/i
    ]) {
      if (stalePattern.test(changelog)) {
        failures.push(`CHANGELOG keeps stale claim ${stalePattern}`);
      }
    }

    for (const requiredFact of [
      "schema v2",
      "policy_state",
      "policy_fingerprint",
      "owner",
      "recovery_required",
      "runtime reaper",
      "production dispatch",
      "auth gate",
      "permission",
      "typed terminal",
      "queue_timeout",
      "provider_capacity",
      "npm test -- --maxWorkers=1",
      "docs/design/receipts/S3-T21/",
      "local `2.0.0.0` tarball",
      "127.0.0.1:6768",
      "STAGE4_ADMISSION_CANARY_OK"
    ]) {
      if (!changelog.includes(requiredFact)) {
        failures.push(`CHANGELOG does not record ${requiredFact}`);
      }
    }

    if (!/Production `127\.0\.0\.1:6767` was not switched or mutated\./.test(changelog)) {
      failures.push("CHANGELOG does not preserve the production connector boundary");
    }

    expect(failures).toEqual([]);
  });

  it("downgrades the old design to historical input with clause-by-clause disposition", () => {
    const design = readDoc(OLD_DESIGN_PATH);
    const failures: string[] = [];
    const firstLines = design.split(/\r?\n/).slice(0, 30).join("\n");

    for (const stalePattern of [/最终方案/, /已确认的开发基线/, /confirmed final authority/i]) {
      if (firstLines.match(stalePattern)) {
        failures.push(`old design header still asserts authority with ${stalePattern}`);
      }
    }

    for (const requiredPointer of [SCHEME_PATH, ...STAGE2_ARTIFACTS]) {
      if (!design.includes(requiredPointer)) {
        failures.push(`old design does not cite ${requiredPointer}`);
      }
    }

    for (let clause = 1; clause <= 10; clause += 1) {
      if (!design.includes(`Clause ${clause}`)) {
        failures.push(`old design lacks disposition for Clause ${clause}`);
      }
    }

    if (!/historical input/i.test(firstLines)) {
      failures.push("old design header does not mark the document as historical input");
    }
    if (/all retained/i.test(design) || /全部保留/.test(design)) {
      failures.push("old design uses an all-retained disposition shortcut");
    }

    expect(failures).toEqual([]);
  });
});
