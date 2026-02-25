import React, { useState, useRef } from "react";
import { Database, GitCompare, Copy, Check, AlertTriangle, CheckCircle, TableProperties, Upload } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Sidebar } from "@/components/Sidebar";
import { toast } from "sonner";
import { compareDatabases, TableDiff } from "@/utils/sqlComparator";

const DatabaseComparator = () => {
  const [originalSQL, setOriginalSQL] = useState("");
  const [errorSQL, setErrorSQL] = useState("");
  const [diffs, setDiffs] = useState<TableDiff[]>([]);
  const [hasCompared, setHasCompared] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [copiedAll, setCopiedAll] = useState(false);
  const [includeMissingTables, setIncludeMissingTables] = useState(true);

  const originalFileRef = useRef<HTMLInputElement>(null);
  const errorFileRef = useRef<HTMLInputElement>(null);

  const handleFileLoad = (setter: (val: string) => void) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.name.endsWith('.sql') && !file.name.endsWith('.txt')) {
      toast.error("Please select a .sql or .txt file");
      return;
    }
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      setter(text);
      toast.success(`Loaded: ${file.name}`);
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const handleCompare = () => {
    if (!originalSQL.trim() || !errorSQL.trim()) {
      toast.error("Please paste both database structures before comparing");
      return;
    }
    let results = compareDatabases(originalSQL, errorSQL);
    if (!includeMissingTables) {
      results = results.filter(d => d.type !== 'missing_table');
    }
    setDiffs(results);
    setHasCompared(true);
    if (results.length === 0) {
      toast.success("No differences found! Both structures match.");
    } else {
      toast.info(`Found differences in ${results.length} table(s)`);
    }
  };

  const handleCopy = async (sql: string, index: number) => {
    await navigator.clipboard.writeText(sql);
    setCopiedIndex(index);
    toast.success("SQL copied!");
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleCopyAll = async () => {
    const allSQL = diffs.map(d => `-- Fix for table: ${d.tableName}\n${d.fixSQL}`).join('\n\n');
    await navigator.clipboard.writeText(allSQL);
    setCopiedAll(true);
    toast.success("All fix SQL copied!");
    setTimeout(() => setCopiedAll(false), 2000);
  };

  const handleClear = () => {
    setOriginalSQL("");
    setErrorSQL("");
    setDiffs([]);
    setHasCompared(false);
  };

  return (
    <Sidebar>
      <div className="p-4 md:p-8 max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-primary/10 rounded-xl">
            <GitCompare className="w-7 h-7 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-foreground">Database Structure Comparator</h1>
            <p className="text-sm text-muted-foreground">Compare phpMyAdmin exports & generate fix SQL</p>
          </div>
        </div>

        {/* Steps Guide */}
        <Card className="p-4 bg-accent/5 border-accent/20">
          <div className="flex flex-wrap gap-4 text-sm text-muted-foreground">
            <span className="flex items-center gap-1.5"><span className="w-5 h-5 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xs font-bold">1</span> Paste or upload original structure</span>
            <span className="flex items-center gap-1.5"><span className="w-5 h-5 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xs font-bold">2</span> Paste or upload error structure</span>
            <span className="flex items-center gap-1.5"><span className="w-5 h-5 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xs font-bold">3</span> Click Compare</span>
            <span className="flex items-center gap-1.5"><span className="w-5 h-5 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-xs font-bold">4</span> Copy & execute fix SQL</span>
          </div>
        </Card>

        {/* Input Areas */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Card className="p-4 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-success" />
                <h2 className="font-semibold text-foreground text-sm">Original (Correct) Structure</h2>
              </div>
              <Button
                size="sm"
                variant="outline"
                className="gap-1.5 text-xs"
                onClick={() => originalFileRef.current?.click()}
              >
                <Upload className="w-3.5 h-3.5" />
                Load .sql File
              </Button>
              <input
                ref={originalFileRef}
                type="file"
                accept=".sql,.txt"
                className="hidden"
                onChange={handleFileLoad(setOriginalSQL)}
              />
            </div>
            <Textarea
              placeholder="Paste your original/correct phpMyAdmin SQL export here...&#10;&#10;Example:&#10;CREATE TABLE `users` (&#10;  `id` int(11) NOT NULL AUTO_INCREMENT,&#10;  `name` varchar(255) NOT NULL,&#10;  PRIMARY KEY (`id`)&#10;) ENGINE=InnoDB;"
              value={originalSQL}
              onChange={(e) => setOriginalSQL(e.target.value)}
              className="min-h-[250px] font-mono text-xs bg-background border-input"
            />
          </Card>

          <Card className="p-4 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-destructive" />
                <h2 className="font-semibold text-foreground text-sm">Error / Incomplete Structure</h2>
              </div>
              <Button
                size="sm"
                variant="outline"
                className="gap-1.5 text-xs"
                onClick={() => errorFileRef.current?.click()}
              >
                <Upload className="w-3.5 h-3.5" />
                Load .sql File
              </Button>
              <input
                ref={errorFileRef}
                type="file"
                accept=".sql,.txt"
                className="hidden"
                onChange={handleFileLoad(setErrorSQL)}
              />
            </div>
            <Textarea
              placeholder="Paste your error/incomplete phpMyAdmin SQL export here...&#10;&#10;This is the database that needs to be fixed to match the original."
              value={errorSQL}
              onChange={(e) => setErrorSQL(e.target.value)}
              className="min-h-[250px] font-mono text-xs bg-background border-input"
            />
          </Card>
        </div>

        {/* Options */}
        <Card className="p-4">
          <div className="flex items-center gap-2">
            <Checkbox
              id="includeMissingTables"
              checked={includeMissingTables}
              onCheckedChange={(checked) => setIncludeMissingTables(checked === true)}
            />
            <Label htmlFor="includeMissingTables" className="text-sm cursor-pointer">
              Include missing tables (generate CREATE TABLE for tables not found in error database)
            </Label>
          </div>
        </Card>

        {/* Action Buttons */}
        <div className="flex gap-3">
          <Button onClick={handleCompare} className="gap-2">
            <GitCompare className="w-4 h-4" />
            Compare Databases
          </Button>
          <Button onClick={handleClear} variant="outline" className="gap-2">
            Clear All
          </Button>
          {diffs.length > 0 && (
            <Button onClick={handleCopyAll} variant="secondary" className="gap-2 ml-auto">
              {copiedAll ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              Copy All Fix SQL
            </Button>
          )}
        </div>

        {/* Results */}
        {hasCompared && (
          <div className="space-y-4">
            {diffs.length === 0 ? (
              <Card className="p-6 text-center">
                <CheckCircle className="w-10 h-10 text-success mx-auto mb-2" />
                <p className="font-semibold text-foreground">Structures Match!</p>
                <p className="text-sm text-muted-foreground">No differences found between the two database structures.</p>
              </Card>
            ) : (
              <>
                <h2 className="text-lg font-semibold text-foreground">
                  Found {diffs.length} difference{diffs.length !== 1 ? 's' : ''}
                </h2>
                {diffs.map((diff, idx) => (
                  <Card key={idx} className="overflow-hidden">
                    {/* Table Header */}
                    <div className="flex items-center justify-between p-4 bg-accent/10 border-b border-border">
                      <div className="flex items-center gap-2">
                        <TableProperties className="w-4 h-4 text-primary" />
                        <span className="font-semibold text-foreground">{diff.tableName}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${
                          diff.type === 'missing_table' ? 'bg-destructive/10 text-destructive' :
                          diff.type === 'missing_columns' ? 'bg-yellow-500/10 text-yellow-600' :
                          diff.type === 'extra_columns' ? 'bg-blue-500/10 text-blue-600' :
                          'bg-orange-500/10 text-orange-600'
                        }`}>
                          {diff.type === 'missing_table' ? 'Missing Table' :
                           diff.type === 'missing_columns' ? 'Missing Columns' :
                           diff.type === 'extra_columns' ? 'Extra Columns' :
                           diff.type === 'modified_columns' ? 'Modified' : 'Multiple Issues'}
                        </span>
                      </div>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleCopy(diff.fixSQL, idx)}
                        className="gap-1.5 text-xs"
                      >
                        {copiedIndex === idx ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                        Copy Fix SQL
                      </Button>
                    </div>

                    {/* Details */}
                    <div className="p-4 space-y-2">
                      <ul className="space-y-1">
                        {diff.details.map((detail, dIdx) => (
                          <li key={dIdx} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="text-primary mt-0.5">•</span>
                            {detail}
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* SQL Fix */}
                    <div className="border-t border-border bg-[hsl(var(--terminal-bg))] p-4">
                      <p className="text-xs text-muted-foreground mb-2">Fix SQL:</p>
                      <pre className="text-xs text-[hsl(var(--terminal-text))] whitespace-pre-wrap break-all font-mono">
                        {diff.fixSQL}
                      </pre>
                    </div>
                  </Card>
                ))}
              </>
            )}
          </div>
        )}
      </div>
    </Sidebar>
  );
};

export default DatabaseComparator;
