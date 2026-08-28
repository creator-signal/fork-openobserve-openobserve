import { readdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

const workflowsDirectory = fileURLToPath(new URL("../workflows/", import.meta.url));
const allowedRunnerLabels = new Set([
  "macos-latest",
  "ubuntu-24.04-arm",
  "ubuntu-latest",
  "windows-latest",
]);
const allowedRunnerExpressions = new Map([
  ["${{ matrix.os }}", "release.yml"],
]);
const forbiddenPatterns = [
  [/\bself-hosted\b/i, "self-hosted runner"],
  [/ubicloud/i, "Ubicloud runner"],
  [/eks-openobserve/i, "OpenObserve EKS runner"],
  [/(?:ubuntu|windows|macos)-[^\s'\"]*-\d+-cores\b/i, "larger runner"],
];

const unquote = (value) => value.replace(/^(?:"([\s\S]*)"|'([\s\S]*)')$/, "$1$2");
const workflowFiles = readdirSync(workflowsDirectory)
  .filter((file) => /\.ya?ml$/i.test(file))
  .sort();
const errors = [];
let runnerCount = 0;

for (const file of workflowFiles) {
  const path = join(workflowsDirectory, file);
  const source = readFileSync(path, "utf8");
  const lines = source.split(/\r?\n/);

  for (const [pattern, description] of forbiddenPatterns) {
    const match = source.match(pattern);
    if (match) {
      const line = source.slice(0, match.index).split(/\r?\n/).length;
      errors.push(`${file}:${line} contains a ${description} reference (${match[0]})`);
    }
  }

  for (const [index, line] of lines.entries()) {
    const match = line.match(/^\s*runs-on:\s*(.*?)\s*$/);
    if (!match) continue;

    runnerCount += 1;
    const value = unquote(match[1].trim());
    const location = `${file}:${index + 1}`;

    if (!value) {
      errors.push(`${location} must use a scalar public GitHub-hosted runner label`);
      continue;
    }

    if (allowedRunnerLabels.has(value)) continue;

    const expressionFile = allowedRunnerExpressions.get(value);
    if (expressionFile === basename(file)) {
      const matrixLabels = lines
        .map((candidate) => candidate.match(/^\s*(?:-\s+)?os:\s*(.*?)\s*$/)?.[1])
        .filter(Boolean)
        .map((candidate) => unquote(candidate));

      if (matrixLabels.length === 0) {
        errors.push(`${location} uses matrix.os without any declared os labels`);
      }
      for (const label of matrixLabels) {
        if (!allowedRunnerLabels.has(label)) {
          errors.push(`${file} matrix.os selects unsupported runner label ${label}`);
        }
      }
      continue;
    }

    errors.push(`${location} selects unsupported runner ${value}`);
  }
}

if (errors.length > 0) {
  console.error("Public runner policy failed:\n" + errors.map((error) => `- ${error}`).join("\n"));
  process.exit(1);
}

console.log(
  `Public runner policy passed for ${runnerCount} jobs across ${workflowFiles.length} workflows.`,
);
