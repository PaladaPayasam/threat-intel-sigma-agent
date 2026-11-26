import { Fragment, useMemo, useState } from "react";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowUpDown, ChevronDown, ChevronRight, Database, ShieldAlert } from "lucide-react";
import type { ExtractedCTI, RetrievedRuleReference } from "../types";

interface ReferenceTablesProps {
  retrievedRules: RetrievedRuleReference[];
  extractedCti: ExtractedCTI | null | undefined;
}

interface IndicatorRow {
  kind: "MITRE ATT&CK" | "Behavior" | "IoC";
  value: string;
}

const ruleColumnHelper = createColumnHelper<RetrievedRuleReference>();
const indicatorColumnHelper = createColumnHelper<IndicatorRow>();

export function ReferenceTables({
  retrievedRules,
  extractedCti,
}: ReferenceTablesProps) {
  const [ruleSorting, setRuleSorting] = useState<SortingState>([]);
  const [indicatorFilter, setIndicatorFilter] = useState("");
  const [expandedRuleTitle, setExpandedRuleTitle] = useState<string | null>(null);

  const ruleColumns = useMemo(
    () => [
      ruleColumnHelper.accessor("title", {
        header: "SigmaHQ Reference Rule",
        cell: (info) => {
          const title = info.getValue();
          const isExpanded = expandedRuleTitle === title;
          return (
            <button
              type="button"
              onClick={() => setExpandedRuleTitle(isExpanded ? null : title)}
              className="flex items-center gap-1.5 text-left font-medium text-sky-300 hover:text-sky-200"
            >
              {isExpanded ? (
                <ChevronDown className="h-4 w-4 shrink-0" />
              ) : (
                <ChevronRight className="h-4 w-4 shrink-0" />
              )}
              <span>{title}</span>
            </button>
          );
        },
      }),
      ruleColumnHelper.accessor(
        (row) =>
          `${String(row.logsource.product ?? "*")} / ${String(
            row.logsource.category ?? row.logsource.service ?? "*"
          )}`,
        {
          id: "logsource",
          header: "Logsource",
          cell: (info) => (
            <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-300">
              {info.getValue()}
            </span>
          ),
        }
      ),
      ruleColumnHelper.accessor("detection_fields", {
        header: "Grounded Sigma Fields",
        enableSorting: false,
        cell: (info) => (
          <div className="flex flex-wrap gap-1">
            {info.getValue().slice(0, 6).map((field) => (
              <span
                key={field}
                className="rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[11px] text-emerald-300"
              >
                {field}
              </span>
            ))}
          </div>
        ),
      }),
      ruleColumnHelper.accessor("score", {
        header: "RRF Score",
        cell: (info) => {
          const score = info.getValue();
          return (
            <span className="font-mono text-xs text-slate-300">
              {score !== null && score !== undefined ? score.toFixed(3) : "—"}
            </span>
          );
        },
      }),
    ],
    [expandedRuleTitle]
  );

  const rulesTable = useReactTable({
    data: retrievedRules,
    columns: ruleColumns,
    state: { sorting: ruleSorting },
    onSortingChange: setRuleSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const indicatorRows = useMemo<IndicatorRow[]>(() => {
    if (!extractedCti) return [];
    return [
      ...extractedCti.mitre_attack_tags.map((tag) => ({
        kind: "MITRE ATT&CK" as const,
        value: tag,
      })),
      ...extractedCti.suspicious_behaviors.map((b) => ({
        kind: "Behavior" as const,
        value: b,
      })),
      ...extractedCti.iocs.map((ioc) => ({
        kind: "IoC" as const,
        value: ioc,
      })),
    ];
  }, [extractedCti]);

  const indicatorColumns = useMemo(
    () => [
      indicatorColumnHelper.accessor("kind", {
        header: "Category",
        cell: (info) => {
          const kind = info.getValue();
          const style =
            kind === "MITRE ATT&CK"
              ? "border-purple-500/40 bg-purple-500/10 text-purple-300"
              : kind === "IoC"
              ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
              : "border-cyan-500/40 bg-cyan-500/10 text-cyan-300";
          return (
            <span
              className={`inline-block rounded-full border px-2 py-0.5 text-[11px] font-medium ${style}`}
            >
              {kind}
            </span>
          );
        },
      }),
      indicatorColumnHelper.accessor("value", {
        header: "Extracted Technique / Indicator",
        cell: (info) => (
          <span className="break-all font-mono text-xs text-slate-200">
            {info.getValue()}
          </span>
        ),
      }),
    ],
    []
  );

  const indicatorsTable = useReactTable({
    data: indicatorRows,
    columns: indicatorColumns,
    state: { globalFilter: indicatorFilter },
    onGlobalFilterChange: setIndicatorFilter,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  });

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
      {/* Grounded SigmaHQ Reference Rules (TanStack Table) */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-sky-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Grounded SigmaHQ Reference Rules ({retrievedRules.length})
            </h3>
          </div>
          <span className="text-xs text-slate-400">
            Click a rule title to inspect YAML
          </span>
        </div>

        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 text-slate-400">
              {rulesTable.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <th key={header.id} className="px-3 py-2 font-medium">
                      {header.column.getCanSort() ? (
                        <button
                          type="button"
                          onClick={header.column.getToggleSortingHandler()}
                          className="inline-flex items-center gap-1 hover:text-slate-200"
                        >
                          {flexRender(
                            header.column.columnDef.header,
                            header.getContext()
                          )}
                          <ArrowUpDown className="h-3 w-3" />
                        </button>
                      ) : (
                        flexRender(
                          header.column.columnDef.header,
                          header.getContext()
                        )
                      )}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {rulesTable.getRowModel().rows.length === 0 ? (
                <tr>
                  <td
                    colSpan={4}
                    className="px-3 py-6 text-center text-slate-500"
                  >
                    Run the pipeline to retrieve grounded SigmaHQ rules via Qdrant Hybrid RAG.
                  </td>
                </tr>
              ) : (
                rulesTable.getRowModel().rows.map((row) => {
                  const isExpanded = expandedRuleTitle === row.original.title;
                  return (
                    <Fragment key={row.id}>
                      <tr
                        className="transition-colors hover:bg-slate-800/40"
                      >
                        {row.getVisibleCells().map((cell) => (
                          <td key={cell.id} className="px-3 py-2.5 align-top">
                            {flexRender(
                              cell.column.columnDef.cell,
                              cell.getContext()
                            )}
                          </td>
                        ))}
                      </tr>
                      {isExpanded && (
                        <tr className="bg-slate-950/90">
                          <td colSpan={4} className="px-3 py-3">
                            <pre className="max-h-56 overflow-auto rounded border border-slate-800 bg-slate-950 p-3 font-mono text-[11px] text-slate-300">
                              {row.original.raw_yaml}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Extracted MITRE ATT&CK Techniques & IoCs (TanStack Table) */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-purple-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Extracted MITRE ATT&CK & IoCs ({indicatorRows.length})
            </h3>
          </div>
          <input
            type="text"
            value={indicatorFilter}
            onChange={(e) => setIndicatorFilter(e.target.value)}
            placeholder="Filter TTPs or IoCs..."
            className="rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1 text-xs text-slate-200 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
          />
        </div>

        <div className="max-h-80 overflow-auto rounded-lg border border-slate-800">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-slate-950 text-slate-400">
              {indicatorsTable.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <th key={header.id} className="px-3 py-2 font-medium">
                      {flexRender(
                        header.column.columnDef.header,
                        header.getContext()
                      )}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {indicatorsTable.getRowModel().rows.length === 0 ? (
                <tr>
                  <td
                    colSpan={2}
                    className="px-3 py-6 text-center text-slate-500"
                  >
                    Extracted MITRE ATT&CK tags, behaviors, and IoCs will appear here.
                  </td>
                </tr>
              ) : (
                indicatorsTable.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    className="transition-colors hover:bg-slate-800/40"
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="px-3 py-2 align-top">
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext()
                        )}
                      </td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
