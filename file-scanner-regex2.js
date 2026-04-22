#!/usr/bin/env node

/**
 * HQL Literal Scanner
 * 
 * Scans Java source files for HQL queries containing:
 *   - Boolean literals  : = '0', = '1', = 0, = 1, <> '0' etc.
 *   - Date literals     : = '9999-12-31', > '2024-01-01' etc.
 *   - Timestamp lits    : > '2024-01-01 00:00:00' etc.
 *   - Numeric strings   : = '5', > '100' etc.
 *   - Underscored names : ROW_CREAT_TS, CANC_IND etc. (any identifier with _)
 * 
 * Skips:
 *   - Variables whose name starts with 'SQL_' (treated as native SQL)
 *   - createNativeQuery(...) calls
 * 
 * Usage:
 *   node hql-scanner.js --root ./src
 *   node hql-scanner.js --root ./src --output report.json
 *   node hql-scanner.js --root ./src --type boolean_quoted,boolean_unquoted
 *   node hql-scanner.js --root ./src --type underscored_identifier
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
    },

    underscored_identifier: {
        label   : 'Underscored identifier (likely DB column name)',
        example : 'ROW_CREAT_TS, CANC_IND, row_upd_ts',
        fix     : 'Replace with Java field path (e.g. auditInfo.createdTimestamp)',
        // Matches any identifier containing at least one underscore.
        // Word boundaries avoid matching inside longer tokens.
        regex   : /\b[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+\b/g,
        // Strip string literal contents (e.g. filter value 'PROD_ENV')
        // and HQL named parameters (:some_param) before matching so we
        // only find underscored identifiers in the HQL structure itself
        preprocess: (hql) => hql
            // mask single-quoted literals, preserve length
            .replace(/'[^']*'/g, (m) =>
                "'" + ' '.repeat(Math.max(0, m.length - 2)) + "'")
            // mask named params :snake_case
            .replace(/:[A-Za-z_][A-Za-z0-9_]*/g, (m) => ' '.repeat(m.length)),
        // HQL / standard SQL functions that legitimately contain underscores
        exclude: new Set([
            'current_timestamp',
            'current_date',
            'current_time',
            'group_concat',
            'string_agg',
            'session_user',
            'system_user',
            'array_agg',
            'json_object',
            'json_array',
            'date_trunc',
            'date_part',
            'date_format',
            'to_char',
            'to_date'
        ]),
        extract : (m) => m[0].trim()
    }
};

// ─── HQL extraction ───────────────────────────────────────────────────────────

/**
 * Extracts HQL string fragments from Java source.
 * Handles:
 *   - Single-line strings     : "select e from EventBO"
 *   - Concatenated strings    : "select e " + "from EventBO"
 *   - Multi-line with +       : "select e \n" + "from EventBO"
 *   - createQuery / createSelectionQuery / createMutationQuery calls
 * 
 * Skips:
 *   - createNativeQuery(...) — those are native SQL, not HQL
 *   - Variables whose name starts with SQL_ — convention for native SQL
 * 
 * Returns array of { value, startLine, method, varName }
 */
function extractHqlFragments(source) {
    const result = [];

    // Match HQL-specific method calls — explicitly excluding createNativeQuery
    const hqlMethodPattern =
        /\b(createQuery|createSelectionQuery|createMutationQuery)\s*\(/g;
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
    // e.g.  String hql = "select ... " + "from ... " + "where ...";
    // Handles concatenated strings across multiple lines.
    // Captures variable name so we can skip SQL_* prefixed ones.
    const assignPattern =
        /(?:private\s+)?(?:static\s+)?(?:final\s+)?(?:String|StringBuilder)\s+(\w+)\s*=\s*((?:"(?:[^"\\]|\\.)*"\s*(?:\+\s*)?)+);/g;

    while ((match = assignPattern.exec(source)) !== null) {
        const varName     = match[1];
        const assignValue = match[2];
        const startLine   = source.substring(0, match.index).split('\n').length;

        // Skip native SQL variables by naming convention
        if (varName.toUpperCase().startsWith('SQL_')) continue;

        // Extract and join ALL string literal contents in the assignment
        // e.g.  "select " + "from X" → "select from X"
        const strPattern = /"((?:[^"\\]|\\.)*)"/g;
        const parts = [];
        let strMatch;
        while ((strMatch = strPattern.exec(assignValue)) !== null) {
            parts.push(strMatch[1]);
        }
        const raw = parts.join('')
            .replace(/\\n/g, ' ')
            .replace(/\\t/g, ' ')
            .replace(/\\r/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();

        // Only include if it looks like HQL (has FROM keyword)
        if (/\bfrom\b/i.test(raw)) {
            result.push({
                value   : raw,
                startLine,
                method  : 'variable',
                varName
            });
        }
    }

    return result;
}

// ─── Issue detection ──────────────────────────────────────────────────────────

function detectIssues(hqlFragment, enabledTypes) {
    const issues = [];

    for (const [type, def] of Object.entries(PATTERNS)) {
        if (enabledTypes && !enabledTypes.includes(type)) continue;
        if (def.preFilter && !def.preFilter(hqlFragment)) continue;

        // Preprocess hides content we shouldn't match against (e.g. 
        // string literal contents), while keeping indices aligned
        // so getContext still points to the right place in the original.
        const target = def.preprocess ? def.preprocess(hqlFragment) : hqlFragment;

        def.regex.lastIndex = 0;
        let m;
        while ((m = def.regex.exec(target)) !== null) {
            const matched = m[0].trim();

            // Exclusion list — lets patterns whitelist legitimate tokens
            // e.g. current_timestamp shouldn't flag underscored_identifier
            if (def.exclude && def.exclude.has(matched.toLowerCase())) continue;

            issues.push({
                type,
                label   : def.label,
                fix     : def.fix,
                matched,
                context : getContext(hqlFragment, m.index, 40)
            });
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
    console.log(`    Skip  : createNativeQuery(...) calls, SQL_* variables`);
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
            'underscored_identifier'
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
