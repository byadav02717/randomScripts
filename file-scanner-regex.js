#!/usr/bin/env node

/**
 * HQL Literal Scanner
 * 
 * Scans Java source files for HQL queries containing:
 *   - Boolean literals : = '0', = '1', = 0, = 1, <> '0' etc.
 *   - Date literals    : = '9999-12-31', > '2024-01-01' etc.
 *   - Timestamp lits   : > '2024-01-01 00:00:00' etc.
 *   - Numeric strings  : = '5', > '100' etc.
 *   - Column names     : ROW_CREAT_TS, CANC_IND etc.
 * 
 * Usage:
 *   node hql-scanner.js --root ./src
 *   node hql-scanner.js --root ./src --output report.json
 *   node hql-scanner.js --root ./src --type boolean
 *   node hql-scanner.js --root ./src --type boolean,date
 *   node hql-scanner.js --root ./src --columns ROW_CREAT_TS,CANC_IND
 */

const fs   = require('fs');
const path = require('path');

// ─── CLI args ────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

function getArg(name) {
    const i = args.indexOf(`--${name}`);
    return i !== -1 ? args[i + 1] : null;
}

const ROOT_DIR     = getArg('root')   || '.';
const OUTPUT_FILE  = getArg('output') || null;
const TYPE_FILTER  = getArg('type')   ? getArg('type').split(',') : null;
const EXTRA_COLS   = getArg('columns')? getArg('columns').split(',') : [];

// ─── Patterns ────────────────────────────────────────────────────────────────

const PATTERNS = {

    boolean_quoted: {
        label   : 'Boolean quoted literal',
        example : "= '0' or = '1'",
        fix     : "Replace '0' → false, '1' → true",
        regex   : /(\s*(?:=|<>|!=)\s*)(['"])([01])\2(?=\s|$)/gi,
        extract : (m) => m[0].trim()
    },

    boolean_unquoted: {
        label   : 'Boolean unquoted literal',
        example : '= 0 or = 1 (at end or before space)',
        fix     : 'Replace 0 → false, 1 → true',
        regex   : /(\s*(?:=|<>|!=)\s*)([01])(?=\s|$)/g,
        extract : (m) => m[0].trim()
    },

    date_literal: {
        label   : 'Date string literal',
        example : "> '9999-12-31'",
        fix     : "Wrap with {d '...'} or use named parameter",
        // Timestamp must be tested first to avoid partial match
        regex   : /([><=!<>]+\s*)'(\d{4}-\d{2}-\d{2})(?!\s*\d{2}:\d{2})'/g,
        extract : (m) => m[0].trim()
    },

    timestamp_literal: {
        label   : 'Timestamp string literal',
        example : "> '2024-01-01 00:00:00'",
        fix     : "Wrap with {ts '...'} or use named parameter",
        regex   : /([><=!<>]+\s*)'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'/g,
        extract : (m) => m[0].trim()
    },

    numeric_string: {
        label   : 'Numeric string literal',
        example : "= '5' or > '100'",
        fix     : "Strip quotes: = '5' → = 5",
        regex   : /([><=!<>]+\s*)'(-?\d+(?:\.\d+)?)'/g,
        // Skip date-shaped strings (already handled above)
        preFilter: (snippet) => !/'\d{4}-\d{2}-\d{2}/.test(snippet),
        extract : (m) => m[0].trim()
    }
};

// Known DB column names that should never appear in HQL
const COLUMN_NAMES = [
    'ROW_CREAT_TS',
    'ROW_UPDT_TS',
    'ROW_CREAT_USER_ID',
    'ROW_UPDT_USER_ID',
    'CANC_IND',
    'ACTV_IND',
    'DEL_IND',
    'DELT_IND',
    ...EXTRA_COLS
];

// ─── HQL extraction ───────────────────────────────────────────────────────────

/**
 * Extracts HQL string fragments from Java source.
 * Handles:
 *   - Single-line strings     : "select e from EventBO"
 *   - Concatenated strings    : "select e " + "from EventBO"
 *   - Multi-line with +       : "select e \n" + "from EventBO"
 *   - createQuery / createSelectionQuery / createMutationQuery / createNativeQuery calls
 * 
 * Returns array of { value, startLine }
 */
function extractHqlFragments(source) {
    const lines  = source.split('\n');
    const result = [];

    // Match string literals (including concatenated ones on one logical line)
    // Strategy: find createQuery/createSelectionQuery/createMutationQuery
    // calls and grab the string argument across concatenation lines

    const hqlMethodPattern = /\b(createQuery|createSelectionQuery|createMutationQuery|createNativeQuery)\s*\(/g;
    let match;

    while ((match = hqlMethodPattern.exec(source)) !== null) {
        const startPos  = match.index;
        const startLine = source.substring(0, startPos).split('\n').length;

        // Extract everything from the opening ( to the closing )
        // Walk forward collecting string content
        let depth      = 0;
        let inside     = false;
        let collected  = '';
        let i          = match.index + match[0].length - 1; // position of '('

        for (; i < source.length; i++) {
            const ch = source[i];
            if (ch === '(') { depth++; inside = true; continue; }
            if (ch === ')') { depth--; if (depth === 0) break; continue; }
            if (inside) collected += ch;
        }

        // Strip Java string syntax — quotes, + operators, whitespace, \n \t escapes
        const hqlValue = collected
            .replace(/\\n/g, ' ')
            .replace(/\\t/g, ' ')
            .replace(/\\r/g, ' ')
            .replace(/"\s*\+\s*"/g, ' ')   // "..." + "..."  → concat
            .replace(/"\s*\+\s*\n\s*"/g, ' ')
            .replace(/^[^"]*"/, '')         // leading non-string content
            .replace(/"[^"]*$/, '')         // trailing non-string content
            .replace(/"/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();

        if (hqlValue.length > 5) {
            result.push({ value: hqlValue, startLine, method: match[1] });
        }
    }

    // Also catch string variables assigned HQL-like content
    // e.g.  String hql = "select ... from ... where ..."
    const assignPattern = /(?:String|StringBuilder)\s+\w+\s*=\s*"((?:[^"\\]|\\.)*)"/g;
    while ((match = assignPattern.exec(source)) !== null) {
        const raw       = match[1];
        const startLine = source.substring(0, match.index).split('\n').length;

        // Only include if it looks like HQL (has FROM or WHERE)
        if (/\bfrom\b/i.test(raw)) {
            result.push({ value: raw.replace(/\\n/g, ' ').trim(), startLine, method: 'variable' });
        }
    }

    return result;
}

// ─── Issue detection ──────────────────────────────────────────────────────────

function detectIssues(hqlFragment, enabledTypes) {
    const issues = [];

    // Check each pattern type
    for (const [type, def] of Object.entries(PATTERNS)) {
        if (enabledTypes && !enabledTypes.includes(type)) continue;
        if (def.preFilter && !def.preFilter(hqlFragment)) continue;

        def.regex.lastIndex = 0;
        let m;
        while ((m = def.regex.exec(hqlFragment)) !== null) {
            issues.push({
                type,
                label   : def.label,
                fix     : def.fix,
                matched : m[0].trim(),
                context : getContext(hqlFragment, m.index, 40)
            });
        }
    }

    // Check for raw column names
    if (!enabledTypes || enabledTypes.includes('column')) {
        for (const col of COLUMN_NAMES) {
            const colPattern = new RegExp(`\\b${col}\\b`, 'i');
            if (colPattern.test(hqlFragment)) {
                issues.push({
                    type   : 'column',
                    label  : 'Raw DB column name in HQL',
                    fix    : `Replace ${col} with its Java field path (e.g. auditInfo.createdTimestamp)`,
                    matched: col,
                    context: getContext(hqlFragment,
                        hqlFragment.toUpperCase().indexOf(col.toUpperCase()), 40)
                });
            }
        }
    }

    return issues;
}

function getContext(str, index, radius) {
    const start = Math.max(0, index - radius);
    const end   = Math.min(str.length, index + radius);
    const pre   = start > 0 ? '...' : '';
    const post  = end < str.length ? '...' : '';
    return pre + str.substring(start, end).trim() + post;
}

// ─── File walker ──────────────────────────────────────────────────────────────

function walkDir(dir, fileList = []) {
    if (!fs.existsSync(dir)) {
        console.error(`Directory not found: ${dir}`);
        process.exit(1);
    }
    for (const entry of fs.readdirSync(dir)) {
        const full = path.join(dir, entry);
        const stat = fs.statSync(full);
        if (stat.isDirectory()) {
            // Skip common non-source dirs
            if (['node_modules', '.git', 'target', 'build', '.idea'].includes(entry)) continue;
            walkDir(full, fileList);
        } else if (entry.endsWith('.java') || entry.endsWith('.xml')) {
            fileList.push(full);
        }
    }
    return fileList;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

function main() {
    console.log(`\n🔍  HQL Literal Scanner`);
    console.log(`    Root  : ${path.resolve(ROOT_DIR)}`);
    console.log(`    Types : ${TYPE_FILTER ? TYPE_FILTER.join(', ') : 'all'}`);
    if (EXTRA_COLS.length) console.log(`    Extra columns: ${EXTRA_COLS.join(', ')}`);
    console.log('');

    const files   = walkDir(ROOT_DIR);
    const report  = [];
    let totalIssues = 0;

    for (const file of files) {
        const source    = fs.readFileSync(file, 'utf8');
        const fragments = extractHqlFragments(source);
        const fileIssues = [];

        for (const frag of fragments) {
            const issues = detectIssues(frag.value, TYPE_FILTER);
            if (issues.length) {
                fileIssues.push({
                    line   : frag.startLine,
                    method : frag.method,
                    hql    : frag.value.substring(0, 120) + (frag.value.length > 120 ? '...' : ''),
                    issues
                });
                totalIssues += issues.length;
            }
        }

        if (fileIssues.length) {
            report.push({ file: path.relative(ROOT_DIR, file), findings: fileIssues });
        }
    }

    // ─── Pivot: group findings by issue type ─────────────────────────────────

    const byType = {};   // { type: { label, fix, findings: [] } }

    for (const entry of report) {
        for (const finding of entry.findings) {
            for (const issue of finding.issues) {
                if (!byType[issue.type]) {
                    byType[issue.type] = {
                        label   : issue.label,
                        fix     : issue.fix,
                        findings: []
                    };
                }
                byType[issue.type].findings.push({
                    file   : entry.file,
                    line   : finding.line,
                    method : finding.method,
                    matched: issue.matched,
                    context: issue.context,
                    hql    : finding.hql
                });
            }
        }
    }

    // ─── Console output grouped by type ──────────────────────────────────────

    if (report.length === 0) {
        console.log('✅  No issues found.');
    } else {
        // Preserve a stable ordering for readability
        const typeOrder = [
            'boolean_quoted',
            'boolean_unquoted',
            'date_literal',
            'timestamp_literal',
            'numeric_string',
            'column'
        ];

        for (const type of typeOrder) {
            if (!byType[type]) continue;
            const group = byType[type];

            console.log('═'.repeat(70));
            console.log(`🏷️   ${group.label.toUpperCase()}   (${group.findings.length} occurrences)`);
            console.log(`    fix: ${group.fix}`);
            console.log('═'.repeat(70));

            for (const f of group.findings) {
                console.log(`  📄  ${f.file}  :  line ~${f.line}  [${f.method}]`);
                console.log(`      matched : "${f.matched}"`);
                console.log(`      context : ${f.context}`);
                console.log(`      hql     : ${f.hql}`);
                console.log('');
            }
        }

        // ─── Summary ──────────────────────────────────────────────────────────

        console.log('─'.repeat(70));
        console.log(`📊  Summary`);
        console.log(`    Files scanned : ${files.length}`);
        console.log(`    Files affected: ${report.length}`);
        console.log(`    Total issues  : ${totalIssues}`);
        console.log('');
        console.log(`    Breakdown by type:`);
        for (const type of Object.keys(byType)) {
            console.log(`      ${byType[type].label.padEnd(32)} : ${byType[type].findings.length}`);
        }
        console.log('');
    }

    // ─── JSON output — also grouped by type ──────────────────────────────────

    if (OUTPUT_FILE) {
        const out = {
            scannedAt    : new Date().toISOString(),
            root         : path.resolve(ROOT_DIR),
            filesScanned : files.length,
            filesAffected: report.length,
            totalIssues,
            byType       : Object.fromEntries(
                Object.entries(byType).map(([type, group]) => [
                    type,
                    {
                        label   : group.label,
                        fix     : group.fix,
                        count   : group.findings.length,
                        findings: group.findings
                    }
                ])
            )
        };
        fs.writeFileSync(OUTPUT_FILE, JSON.stringify(out, null, 2));
        console.log(`📁  Report written to: ${OUTPUT_FILE}`);
    }
}

main();
