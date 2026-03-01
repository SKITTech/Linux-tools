export interface TableDef {
  name: string;
  columns: Map<string, ColumnDef>;
  indexes: string[];
  engine?: string;
  charset?: string;
  rawCreate: string;
}

export interface ColumnDef {
  name: string;
  definition: string; // full column definition line
}

export interface TableDiff {
  tableName: string;
  type: 'missing_table' | 'extra_table' | 'extra_columns' | 'missing_columns' | 'modified_columns' | 'mixed';
  details: string[];
  fixSQL: string;
}

/**
 * Extract CREATE TABLE blocks by counting parentheses depth,
 * so nested parens like int(11), decimal(10,3), PRIMARY KEY (`id`) are handled.
 */
function extractCreateTableBlocks(sql: string): { name: string; body: string; suffix: string; raw: string }[] {
  const results: { name: string; body: string; suffix: string; raw: string }[] = [];

  // Find each CREATE TABLE start
  const startRegex = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"]?(\w+)[`"]?\s*\(/gi;
  let startMatch: RegExpExecArray | null;

  while ((startMatch = startRegex.exec(sql)) !== null) {
    const tableName = startMatch[1];
    const bodyStart = startMatch.index + startMatch[0].length;
    
    // Walk forward counting parentheses depth
    let depth = 1;
    let i = bodyStart;
    while (i < sql.length && depth > 0) {
      if (sql[i] === '(') depth++;
      else if (sql[i] === ')') depth--;
      if (depth > 0) i++;
    }

    if (depth !== 0) continue; // malformed, skip

    const body = sql.substring(bodyStart, i);
    
    // Capture suffix (ENGINE=..., DEFAULT CHARSET=..., etc.) up to semicolon
    const afterClose = sql.substring(i + 1);
    const suffixMatch = afterClose.match(/^([^;]*);/);
    const suffix = suffixMatch ? suffixMatch[1].trim() : '';
    const endPos = i + 1 + (suffixMatch ? suffixMatch[0].length : 0);
    
    const raw = sql.substring(startMatch.index, endPos);

    results.push({ name: tableName, body, suffix, raw });
  }

  return results;
}

function parseTables(sql: string): Map<string, TableDef> {
  const tables = new Map<string, TableDef>();
  const blocks = extractCreateTableBlocks(sql);

  for (const block of blocks) {
    const columns = new Map<string, ColumnDef>();
    const indexes: string[] = [];
    
    // Split body by lines
    const lines = block.body.split('\n').map(l => l.trim()).filter(l => l);
    
    for (const line of lines) {
      const cleanLine = line.replace(/,\s*$/, '').trim();
      if (!cleanLine) continue;
      
      // Check if it's an index/key/constraint
      if (/^(PRIMARY\s+KEY|UNIQUE\s+KEY|UNIQUE\s+INDEX|UNIQUE|KEY|INDEX|CONSTRAINT|FOREIGN\s+KEY)/i.test(cleanLine)) {
        indexes.push(cleanLine);
      } else {
        // It's a column definition
        const colMatch = cleanLine.match(/^[`"]?(\w+)[`"]?\s+(.+)$/);
        if (colMatch) {
          columns.set(colMatch[1].toLowerCase(), {
            name: colMatch[1],
            definition: cleanLine,
          });
        }
      }
    }
    
    tables.set(block.name.toLowerCase(), {
      name: block.name,
      columns,
      indexes,
      rawCreate: block.raw,
      engine: block.suffix,
    });
  }
  
  return tables;
}

export function compareDatabases(originalSQL: string, errorSQL: string): TableDiff[] {
  const originalTables = parseTables(originalSQL);
  const errorTables = parseTables(errorSQL);
  const diffs: TableDiff[] = [];

  // Find missing tables (in original but not in error)
  for (const [key, origTable] of originalTables) {
    if (!errorTables.has(key)) {
      diffs.push({
        tableName: origTable.name,
        type: 'missing_table',
        details: [
          `Table \`${origTable.name}\` is completely missing`,
          `Columns: ${Array.from(origTable.columns.values()).map(c => c.name).join(', ')}`,
        ],
        fixSQL: origTable.rawCreate,
      });
      continue;
    }

    const errTable = errorTables.get(key)!;
    const details: string[] = [];
    const fixStatements: string[] = [];

    // Find missing columns
    for (const [colKey, origCol] of origTable.columns) {
      if (!errTable.columns.has(colKey)) {
        details.push(`Missing column: \`${origCol.name}\` — definition: \`${origCol.definition}\``);
        fixStatements.push(`ALTER TABLE \`${origTable.name}\` ADD COLUMN ${origCol.definition};`);
      } else {
        // Check if definition differs
        const errCol = errTable.columns.get(colKey)!;
        const normOrig = origCol.definition.replace(/\s+/g, ' ').toLowerCase();
        const normErr = errCol.definition.replace(/\s+/g, ' ').toLowerCase();
        if (normOrig !== normErr) {
          details.push(`Modified column: \`${origCol.name}\` — expected: \`${origCol.definition}\`, found: \`${errCol.definition}\``);
          fixStatements.push(`ALTER TABLE \`${origTable.name}\` MODIFY COLUMN ${origCol.definition};`);
        }
      }
    }

    // Find extra columns (in error but not in original)
    for (const [colKey, errCol] of errTable.columns) {
      if (!origTable.columns.has(colKey)) {
        details.push(`Extra column (not in original): \`${errCol.name}\``);
        fixStatements.push(`ALTER TABLE \`${origTable.name}\` DROP COLUMN \`${errCol.name}\`;`);
      }
    }

    // Find missing indexes
    for (const origIdx of origTable.indexes) {
      const normOrig = origIdx.replace(/\s+/g, ' ').toLowerCase();
      const found = errTable.indexes.some(ei => ei.replace(/\s+/g, ' ').toLowerCase() === normOrig);
      if (!found) {
        details.push(`Missing index/key: ${origIdx}`);
        fixStatements.push(`ALTER TABLE \`${origTable.name}\` ADD ${origIdx};`);
      }
    }

    if (details.length > 0) {
      const missingCols = details.filter(d => d.startsWith('Missing column'));
      const extraCols = details.filter(d => d.startsWith('Extra column'));
      const modifiedCols = details.filter(d => d.startsWith('Modified column'));
      const missingIdx = details.filter(d => d.startsWith('Missing index'));

      let type: TableDiff['type'];
      if (missingCols.length > 0 && extraCols.length === 0 && modifiedCols.length === 0 && missingIdx.length === 0) {
        type = 'missing_columns';
      } else if (extraCols.length > 0 && missingCols.length === 0 && modifiedCols.length === 0 && missingIdx.length === 0) {
        type = 'extra_columns';
      } else if (modifiedCols.length > 0 && missingCols.length === 0 && extraCols.length === 0 && missingIdx.length === 0) {
        type = 'modified_columns';
      } else {
        type = 'mixed';
      }

      diffs.push({
        tableName: origTable.name,
        type,
        details,
        fixSQL: fixStatements.join('\n'),
      });
    }
  }

  // Tables in error but not in original (extra tables)
  for (const [key, errTable] of errorTables) {
    if (!originalTables.has(key)) {
      diffs.push({
        tableName: errTable.name,
        type: 'extra_table',
        details: [`Extra table \`${errTable.name}\` exists but is not in the original structure`],
        fixSQL: `DROP TABLE IF EXISTS \`${errTable.name}\`;`,
      });
    }
  }

  return diffs;
}
