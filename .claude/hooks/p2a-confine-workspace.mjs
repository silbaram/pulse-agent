#!/usr/bin/env node
/**
 * Plan2Agent Claude Code PreToolUse confinement hook.
 *
 * The hook provides an app-level workspace boundary for Claude's Write/Edit
 * tools and best-effort Bash screening. Bash command-string screening is not
 * airtight: shell syntax, variable expansion, subprocess behavior, interpreter
 * strings, and tool semantics can hide writes. On macOS/Linux, Claude Code's
 * OS-level sandboxed Bash is the actual Part B boundary for subprocesses; on
 * Windows this app-level screen leaves residual risk and should not be treated
 * as a complete sandbox.
 */

import { existsSync, realpathSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

function emitDecision(permissionDecision, permissionDecisionReason) {
  process.stdout.write(`${JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision,
      permissionDecisionReason,
    },
  })}\n`);
}

function deny(reason) {
  emitDecision('deny', reason);
  process.exit(0);
}

function allow(reason) {
  emitDecision('allow', reason);
  process.exit(0);
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let input = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { input += chunk; });
    process.stdin.on('end', () => resolve(input));
    process.stdin.on('error', reject);
  });
}

function canonicalizePath(filePath) {
  const absolute = path.resolve(filePath);
  const tail = [];
  let current = absolute;
  while (!existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) break;
    tail.unshift(path.basename(current));
    current = parent;
  }
  const realBase = realpathSync.native(current);
  return tail.length ? path.join(realBase, ...tail) : realBase;
}

function workspaceRootFromEvent(event) {
  const cwd = typeof event.cwd === 'string' && event.cwd.trim() ? event.cwd : process.cwd();
  return canonicalizePath(cwd);
}

function hasWindowsDrivePrefix(value) {
  return /^[a-zA-Z]:[\\/]/.test(value) || /^\\\\[^\\/]+[\\/][^\\/]+/.test(value);
}

function resolveToolPath(rawPath, workspaceRoot) {
  if (typeof rawPath !== 'string' || !rawPath.trim()) return null;
  const expanded = rawPath.startsWith('~/') || rawPath.startsWith('~\\')
    ? path.join(process.env.HOME || process.env.USERPROFILE || '', rawPath.slice(2))
    : rawPath;
  if (process.platform !== 'win32' && hasWindowsDrivePrefix(expanded)) return expanded;
  const absolute = path.isAbsolute(expanded) || hasWindowsDrivePrefix(expanded)
    ? expanded
    : path.resolve(workspaceRoot, expanded);
  return canonicalizePath(absolute);
}

function normalizeForContainment(filePath) {
  let normalized = path.normalize(filePath);
  if (process.platform === 'win32') normalized = normalized.toLowerCase();
  return normalized.replace(/[\\/]+$/, '');
}

function isPathInsideWorkspace(candidatePath, workspaceRoot) {
  if (process.platform !== 'win32' && hasWindowsDrivePrefix(candidatePath)) return false;
  const candidate = normalizeForContainment(candidatePath);
  const root = normalizeForContainment(workspaceRoot);
  if (candidate === root) return true;
  const relative = path.relative(root, candidate);
  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
}

function shellTokens(command) {
  const tokens = [];
  let current = '';
  let quote = null;
  let escaped = false;
  for (const char of command) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      current += char;
      continue;
    }
    if (quote) {
      if (char === quote) quote = null;
      current += char;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      current += char;
      continue;
    }
    if (/\s/.test(char) || [';', '|', '&', '>', '<'].includes(char)) {
      if (current) tokens.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  if (current) tokens.push(current);
  return tokens.map((token) => token.replace(/^['"]|['"]$/g, ''));
}

function tokenLooksExternalPath(token, workspaceRoot) {
  if (!token || token.startsWith('-')) return false;
  if (!(token.startsWith('/') || token.startsWith('~/') || token.startsWith('~\\') || hasWindowsDrivePrefix(token))) return false;
  try {
    const resolved = resolveToolPath(token, workspaceRoot);
    return resolved ? !isPathInsideWorkspace(resolved, workspaceRoot) : true;
  } catch {
    return true;
  }
}

function checkBash(command, workspaceRoot) {
  if (typeof command !== 'string' || !command.trim()) return 'missing Bash command';
  const compact = command.replace(/\s+/g, ' ').trim();
  const destructive = /(^|[;&|()\s])(rm|rmdir|mv|cp|install|mkdir|touch|chmod|chown|ln|tee|truncate|dd|sed|perl|python(?:\d+(?:\.\d+)?)?|node|bash|sh|zsh|pwsh|powershell)(\s|$)/i;
  if (!destructive.test(compact) && !/[>]{1,2}/.test(compact)) return null;
  const tokens = shellTokens(compact);
  const writeCapableInterpreter = tokens.some((token) => /^(?:.*[\/])?(?:node|python(?:\d+(?:\.\d+)?)?|perl|ruby|php)(?:\.exe)?$/i.test(token));
  if (writeCapableInterpreter) {
    const embeddedPathPattern = /(?:^|[^\w.~/-])((?:~[\/]|[a-zA-Z]:[\\/]|\/)[^'\"\s;|&<>)]*)/g;
    for (const embeddedPath of compact.matchAll(embeddedPathPattern)) {
      if (tokenLooksExternalPath(embeddedPath[1], workspaceRoot)) {
        return `Bash interpreter argument contains an outside-workspace path: ${embeddedPath[1]}`;
      }
    }
  }
  for (const token of tokens) {
    if (tokenLooksExternalPath(token, workspaceRoot)) {
      return `Bash command appears to target outside the workspace: ${token}`;
    }
  }
  if (/(^|\s)(rm|rmdir)\s+(-[^\s]*[rf][^\s]*\s+)*([/]|~(?:[/\\]|$)|[a-zA-Z]:[\\/](?:\s|$))/i.test(compact)) {
    return 'Bash command attempts destructive removal of a root or home path';
  }
  return null;
}

const rawInput = await readStdin();
let event;
try {
  event = JSON.parse(rawInput || '{}');
} catch (error) {
  deny(`Plan2Agent confinement hook could not parse stdin JSON: ${error.message}`);
}

const toolName = event.tool_name;
const toolInput = event.tool_input && typeof event.tool_input === 'object' ? event.tool_input : {};
let workspaceRoot;
try {
  workspaceRoot = workspaceRootFromEvent(event);
} catch (error) {
  deny(`Plan2Agent confinement hook could not canonicalize workspace root: ${error.message}`);
}

if (toolName === 'Write' || toolName === 'Edit') {
  let candidate;
  try {
    candidate = resolveToolPath(toolInput.file_path, workspaceRoot);
  } catch (error) {
    deny(`${toolName} blocked: could not canonicalize ${toolInput.file_path}: ${error.message}`);
  }
  if (!candidate) deny(`${toolName} call is missing tool_input.file_path`);
  if (!isPathInsideWorkspace(candidate, workspaceRoot)) {
    deny(`${toolName} blocked: ${toolInput.file_path} resolves outside workspace ${workspaceRoot}`);
  }
  allow(`${toolName} target remains inside workspace`);
}

if (toolName === 'Bash') {
  const reason = checkBash(toolInput.command, workspaceRoot);
  if (reason) deny(reason);
  allow('Bash command passed Plan2Agent best-effort app-level workspace screen');
}

process.exit(0);
