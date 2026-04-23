#!/usr/bin/env node

/**
 * HQL Literal Scanner
 * 
 * Scans .java files for HQL queries containing:
 *   - Boolean literals  : = '0', = '1', = 0, = 1, <> '0' etc.
 *   - Date literals     : = '9999-12-31', > '2024-01-01' etc.
 *   - Timestamp lits    : > '2024-01-01 00:00:00' etc.
 *   - Numeric strings   : = '5', > '100' etc.
 *   - Underscored names : ROW_CREAT_TS, CANC_IND etc. (any identifier with _)
 * 
 * Skips:
 *   - createNativeQuery(...) calls (native SQL)
 *   - Variables whose name indicates native SQL:
 *       starts with  SQL_       (e.g. SQL_FIND_USER)
 *       ends with    _SQL       (e.g. FIND_USER_SQL)
 *       contains     _SQL_      (e.g. FIND_SQL_QUERY)
 * 
 * Severity:
 *   High   = variable name includes "hql" AND matches any condition
 *   Low    = matched numeric_string AND "hql" not in variable name
 *   Medium = any other matched condition
 * 
 * Usage:
 *   node hql-scanner.js --root ./src
 *   node hql-scanner.js --root ./src --json report.json
 *   node hql-scanner.js --root ./src --xlsx report.xlsx   # needs: npm install exceljs
 *   node hql-scanner.js --root ./src --type boolean_quoted,boolean_unquoted
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
const JSON_FILE    = getArg('json')   || getArg('output') || null; // alias --output
const XLSX_FILE    = getArg('xlsx')   || null;
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
    // Handles concatenated strings across multiple lines (with or
    // without a trailing semicolon). Captures variable name so we
    // can skip SQL_*/*_SQL/*_SQL_* prefixed ones.
    //
    // The outer (...)+ greedily matches as many "..."+"..."  segments
    // as it can. It naturally stops at any token that is not a quote
    // or +, so omitting the trailing ; is safe — the next declaration
    // line won't be consumed.
    const assignPattern =
        /(?:private\s+)?(?:static\s+)?(?:final\s+)?(?:String|StringBuilder)\s+(\w+)\s*=\s*((?:"(?:[^"\\]|\\.)*"\s*(?:\+\s*)?)+)/g;

    while ((match = assignPattern.exec(source)) !== null) {
        const varName     = match[1];
        const assignValue = match[2];
        const startLine   = source.substring(0, match.index).split('\n').length;

        // Skip native SQL variables by naming convention:
        //   starts with  SQL_
        //   ends with    _SQL
        //   contains     _SQL_
        if (isSqlVariableName(varName)) continue;

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

/**
 * Returns true if the variable name indicates a native SQL query.
 * Matches: SQL_* (prefix), *_SQL (suffix), *_SQL_* (infix)
 * Case-insensitive so sql_foo, FOO_SQL, foo_sql_bar all match.
 */
function isSqlVariableName(varName) {
    const upper = varName.toUpperCase();
    return upper.startsWith('SQL_')
        || upper.endsWith('_SQL')
        || upper.includes('_SQL_');
}

/**
 * Returns severity ranking for a finding:
 *   High   = variable name includes "hql" AND matches any condition
 *   Low    = matched numeric_string AND "hql" not in variable name
 *   Medium = any other matched condition
 */
function computeSeverity(varName, type) {
    const hasHql = varName && varName.toLowerCase().includes('hql');
    if (hasHql) return 'High';
    if (type === 'numeric_string') return 'Low';
    return 'Medium';
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
        } else if (entry.endsWith('.java')) {
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
    console.log(`    Skip  : createNativeQuery, SQL_*/*_SQL/*_SQL_* vars`);
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
                    line    : frag.startLine,
                    method  : frag.method,
                    varName : frag.varName || null,
                    hql     : frag.value.substring(0, 120) + (frag.value.length > 120 ? '...' : ''),
                    fullHql : frag.value,    // full HQL for excel export
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
                    file    : entry.file,
                    line    : finding.line,
                    method  : finding.method,
                    varName : finding.varName,
                    matched : issue.matched,
                    context : issue.context,
                    hql     : finding.hql,
                    fullHql : finding.fullHql,
                    severity: computeSeverity(finding.varName, issue.type)
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
                const sev = `[${f.severity}]`.padEnd(8);
                console.log(`  ${sev} 📄  ${f.file}  :  line ~${f.line}  [${f.method}]`);
                console.log(`           matched : "${f.matched}"`);
                console.log(`           context : ${f.context}`);
                console.log(`           hql     : ${f.hql}`);
                console.log('');
            }
        }

        // ─── Summary ──────────────────────────────────────────────────────────

        const sevCounts = { High: 0, Medium: 0, Low: 0 };
        for (const group of Object.values(byType)) {
            for (const f of group.findings) sevCounts[f.severity]++;
        }

        console.log('─'.repeat(70));
        console.log(`📊  Summary`);
        console.log(`    Files scanned : ${files.length}`);
        console.log(`    Files affected: ${report.length}`);
        console.log(`    Total issues  : ${totalIssues}`);
        console.log('');
        console.log(`    Severity:`);
        console.log(`      High    : ${sevCounts.High}`);
        console.log(`      Medium  : ${sevCounts.Medium}`);
        console.log(`      Low     : ${sevCounts.Low}`);
        console.log('');
        console.log(`    Breakdown by type:`);
        for (const type of Object.keys(byType)) {
            console.log(`      ${byType[type].label.padEnd(32)} : ${byType[type].findings.length}`);
        }
        console.log('');
    }

    // ─── JSON output — grouped by type ───────────────────────────────────────

    if (JSON_FILE) {
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
        fs.writeFileSync(JSON_FILE, JSON.stringify(out, null, 2));
        console.log(`📁  JSON  written to: ${JSON_FILE}`);
    }

    // ─── Excel output — flat row format ──────────────────────────────────────

    if (XLSX_FILE) {
        writeExcelReport(XLSX_FILE, byType).catch(err => {
            console.error(`\n❌  Failed to write Excel report: ${err.message}`);
            if (err.code === 'MODULE_NOT_FOUND') {
                console.error(`    Install the dependency once with:\n      npm install exceljs`);
            }
            process.exit(1);
        });
    }
}

// ─── Excel writer ────────────────────────────────────────────────────────────

async function writeExcelReport(outPath, byType) {
    let ExcelJS;
    try {
        ExcelJS = require('exceljs');
    } catch (e) {
        e.code = 'MODULE_NOT_FOUND';
        throw e;
    }

    const workbook = new ExcelJS.Workbook();
    workbook.creator    = 'HQL Literal Scanner';
    workbook.created    = new Date();

    const sheet = workbook.addWorksheet('Findings');

    // Columns the user asked for
    sheet.columns = [
        { header: 'Type of discrepancy', key: 'type',     width: 32 },
        { header: 'File path',           key: 'filePath', width: 60 },
        { header: 'File name',           key: 'fileName', width: 28 },
        { header: 'Variable',            key: 'varName',  width: 28 },
        { header: 'Matched',             key: 'matched',  width: 24 },
        { header: 'HQL',                 key: 'hql',      width: 80 },
        { header: 'Severity',            key: 'severity', width: 10 }
    ];

    // Header styling
    sheet.getRow(1).font      = { bold: true, color: { argb: 'FFFFFFFF' } };
    sheet.getRow(1).fill      = {
        type   : 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FF305496' }
    };
    sheet.getRow(1).alignment = { vertical: 'middle' };

    // Severity color map
    const sevColor = {
        High  : 'FFE06666',  // soft red
        Medium: 'FFFFD966',  // soft amber
        Low   : 'FFB6D7A8'   // soft green
    };

    // Flatten all findings in a stable order (severity desc, then type)
    const sevRank = { High: 0, Medium: 1, Low: 2 };
    const allRows = [];
    for (const [type, group] of Object.entries(byType)) {
        for (const f of group.findings) {
            allRows.push({ type: group.label, ...f });
        }
    }
    allRows.sort((a, b) =>
        sevRank[a.severity] - sevRank[b.severity]
        || a.type.localeCompare(b.type)
        || a.file.localeCompare(b.file)
    );

    for (const r of allRows) {
        const row = sheet.addRow({
            type    : r.type,
            filePath: r.file,
            fileName: path.basename(r.file),
            varName : r.varName || '(inline)',
            matched : r.matched,
            hql     : r.fullHql,
            severity: r.severity
        });
        // Severity cell color
        row.getCell('severity').fill = {
            type   : 'pattern',
            pattern: 'solid',
            fgColor: { argb: sevColor[r.severity] }
        };
        row.getCell('severity').alignment = { horizontal: 'center' };
        row.getCell('hql').alignment      = { wrapText: true, vertical: 'top' };
    }

    // Freeze header row
    sheet.views = [{ state: 'frozen', ySplit: 1 }];

    // Auto-filter on the data range
    sheet.autoFilter = {
        from: { row: 1, column: 1 },
        to  : { row: 1, column: sheet.columns.length }
    };

    await workbook.xlsx.writeFile(outPath);
    console.log(`📁  Excel written to: ${outPath}`);
}

main();
