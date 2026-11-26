import { useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  FileCode2,
  Globe,
  Loader2,
  Play,
  RotateCcw,
  Shield,
  Sparkles,
  Terminal,
} from "lucide-react";
import { checkBackendHealth, streamGenerateSigma } from "./api/streamGenerate";
import { ReferenceTables } from "./components/ReferenceTables";
import { THREAT_PRESETS } from "./presets";
import type {
  ExtractedCTI,
  GenerateResponsePayload,
  RetrievedRuleReference,
  StreamProgressEvent,
  WorkflowNodeName,
} from "./types";

type OutputTab = "sigma" | "splunk" | "sentinel";
type InputMode = "text" | "url";

const PIPELINE_STEPS: { id: WorkflowNodeName; label: string }[] = [
  { id: "extract_cti", label: "Extracting CTI" },
  { id: "rag_grounding", label: "Grounding via Hybrid RAG" },
  { id: "generate_sigma", label: "Generating Sigma YAML" },
  { id: "validate_sigma", label: "Validating with pySigma" },
];

export default function App() {
  const [inputMode, setInputMode] = useState<InputMode>("text");
  const [urlInput, setUrlInput] = useState("");
  const [rawTextInput, setRawTextInput] = useState(THREAT_PRESETS[0].rawText);
  const [activeTab, setActiveTab] = useState<OutputTab>("sigma");
  const [copiedTab, setCopiedTab] = useState<OutputTab | null>(null);

  const [completedNodes, setCompletedNodes] = useState<WorkflowNodeName[]>([]);
  const [activeNode, setActiveNode] = useState<WorkflowNodeName | null>(null);
  const [attempts, setAttempts] = useState(0);
  const [liveCti, setLiveCti] = useState<ExtractedCTI | null>(null);
  const [liveSigmaYaml, setLiveSigmaYaml] = useState<string>("");
  const [result, setResult] = useState<GenerateResponsePayload | null>(null);

  const abortRef = useRef<AbortController | null>(null);

  const healthQuery = useQuery({
    queryKey: ["backend-health"],
    queryFn: checkBackendHealth,
    refetchInterval: 15000,
    retry: 1,
  });

  const generateMutation = useMutation({
    mutationFn: async () => {
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      setCompletedNodes([]);
      setActiveNode("extract_cti");
      setAttempts(0);
      setLiveCti(null);
      setLiveSigmaYaml("");
      setResult(null);

      const payload =
        inputMode === "url"
          ? { url: urlInput.trim(), max_retries: 3 }
          : { raw_text: rawTextInput.trim(), max_retries: 3 };

      return streamGenerateSigma(
        payload,
        {
          onProgress: (event: StreamProgressEvent) => {
            setAttempts(event.attempts);
            setCompletedNodes((prev) =>
              prev.includes(event.node) ? prev : [...prev, event.node]
            );
            if (event.extracted_cti) {
              setLiveCti(event.extracted_cti);
            }
            if (event.sigma_yaml) {
              setLiveSigmaYaml(event.sigma_yaml);
            }

            if (event.node === "extract_cti") setActiveNode("rag_grounding");
            else if (event.node === "rag_grounding")
              setActiveNode("generate_sigma");
            else if (event.node === "generate_sigma")
              setActiveNode("validate_sigma");
            else if (event.node === "validate_sigma") {
              if (event.validation && !event.validation.is_valid) {
                setActiveNode("generate_sigma");
              } else {
                setActiveNode(null);
              }
            }
          },
          onComplete: (finalPayload) => {
            setResult(finalPayload);
            setActiveNode(null);
            setAttempts(finalPayload.attempts);
            if (finalPayload.extracted_cti) {
              setLiveCti(finalPayload.extracted_cti);
            }
            if (finalPayload.sigma_yaml) {
              setLiveSigmaYaml(finalPayload.sigma_yaml);
            }
          },
        },
        controller.signal
      );
    },
  });

  const handleReset = () => {
    abortRef.current?.abort();
    generateMutation.reset();
    setCompletedNodes([]);
    setActiveNode(null);
    setAttempts(0);
    setLiveCti(null);
    setLiveSigmaYaml("");
    setResult(null);
  };

  const sigmaContent = result?.sigma_yaml ?? liveSigmaYaml;
  const splunkContent =
    result?.splunk_spl ?? result?.validation?.splunk_spl ?? "";
  const sentinelContent =
    result?.sentinel_kql ?? result?.validation?.sentinel_kql ?? "";

  const currentOutput =
    activeTab === "sigma"
      ? sigmaContent
      : activeTab === "splunk"
      ? splunkContent
      : sentinelContent;

  const handleCopy = async () => {
    if (!currentOutput) return;
    await navigator.clipboard.writeText(currentOutput);
    setCopiedTab(activeTab);
    setTimeout(() => setCopiedTab(null), 1800);
  };

  const extractedCti = result?.extracted_cti ?? liveCti;
  const retrievedRules: RetrievedRuleReference[] = result?.retrieved_rules ?? [];

  const canSubmit =
    !generateMutation.isPending &&
    (inputMode === "url" ? urlInput.trim().length > 0 : rawTextInput.trim().length > 0);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Header */}
      <header className="border-b border-slate-800/90 bg-slate-900/60 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-4 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-sky-500/30 bg-sky-500/10 text-sky-400">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-white">
                Threat-Intel Sigma Workbench
              </h1>
              <p className="text-xs text-slate-400">
                LangGraph + Hybrid Qdrant RAG + pySigma Multi-SIEM Transpiler
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 rounded-full border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs">
            <Activity
              className={`h-3.5 w-3.5 ${
                healthQuery.isSuccess
                  ? "text-emerald-400"
                  : healthQuery.isError
                  ? "text-rose-400"
                  : "text-amber-400"
              }`}
            />
            <span className="text-slate-300">
              {healthQuery.isSuccess
                ? "API Online (localhost:8000)"
                : healthQuery.isError
                ? "API Offline"
                : "Checking API..."}
            </span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6">
        {/* Live Progress Badges */}
        <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              {PIPELINE_STEPS.map((step, index) => {
                const isDone = completedNodes.includes(step.id);
                const isRunning = activeNode === step.id && generateMutation.isPending;
                return (
                  <div key={step.id} className="flex items-center gap-2">
                    <div
                      className={`flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium transition-all ${
                        isRunning
                          ? "border-sky-500/60 bg-sky-500/15 text-sky-300"
                          : isDone
                          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                          : "border-slate-800 bg-slate-950 text-slate-500"
                      }`}
                    >
                      {isRunning ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : isDone ? (
                        <CheckCircle2 className="h-3.5 w-3.5" />
                      ) : (
                        <span className="inline-block h-2 w-2 rounded-full bg-slate-700" />
                      )}
                      <span>{step.label}</span>
                    </div>
                    {index < PIPELINE_STEPS.length - 1 && (
                      <span className="text-slate-700">→</span>
                    )}
                  </div>
                );
              })}
            </div>

            {attempts > 0 && (
              <span className="rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1 font-mono text-xs text-slate-300">
                Attempts: {attempts}/3
              </span>
            )}
          </div>
        </section>

        {/* Input & Output Split Grid */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Left: CTI Input & Presets */}
          <section className="space-y-4 rounded-xl border border-slate-800 bg-slate-900/70 p-4 lg:col-span-5">
            <div className="flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-sm font-semibold text-white">
                <Sparkles className="h-4 w-4 text-sky-400" />
                Threat Intelligence Input
              </h2>
              <div className="inline-flex rounded-lg border border-slate-800 bg-slate-950 p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setInputMode("text")}
                  className={`rounded-md px-2.5 py-1 font-medium transition ${
                    inputMode === "text"
                      ? "bg-sky-600 text-white"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Raw Text
                </button>
                <button
                  type="button"
                  onClick={() => setInputMode("url")}
                  className={`inline-flex items-center gap-1 rounded-md px-2.5 py-1 font-medium transition ${
                    inputMode === "url"
                      ? "bg-sky-600 text-white"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Globe className="h-3 w-3" />
                  Article URL
                </button>
              </div>
            </div>

            {/* One-Click Presets */}
            <div className="space-y-2">
              <p className="text-xs font-medium text-slate-400">
                One-Click Threat-Intel Presets:
              </p>
              <div className="grid grid-cols-1 gap-2">
                {THREAT_PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => {
                      setInputMode("text");
                      setRawTextInput(preset.rawText);
                    }}
                    className="rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 text-left transition hover:border-sky-500/50 hover:bg-slate-900"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-semibold text-slate-200">
                        {preset.label}
                      </span>
                      <span className="font-mono text-[10px] text-sky-400">
                        {preset.tag}
                      </span>
                    </div>
                    <p className="mt-0.5 text-[11px] text-slate-400">
                      {preset.description}
                    </p>
                  </button>
                ))}
              </div>
            </div>

            {/* Input Box */}
            {inputMode === "url" ? (
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-300">
                  Threat Advisory URL
                </label>
                <input
                  type="url"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="https://thedfirreport.com/..."
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
                />
              </div>
            ) : (
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-300">
                  Threat Report / TTP Snippet
                </label>
                <textarea
                  rows={8}
                  value={rawTextInput}
                  onChange={(e) => setRawTextInput(e.target.value)}
                  placeholder="Paste threat intelligence report text, command-lines, or adversary TTPs..."
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs leading-relaxed text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
                />
              </div>
            )}

            <div className="flex items-center gap-2 pt-1">
              <button
                type="button"
                disabled={!canSubmit}
                onClick={() => generateMutation.mutate()}
                className="inline-flex flex-1 items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-2.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {generateMutation.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Running Agent Pipeline...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" />
                    Generate Sigma & SIEM Queries
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={handleReset}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-xs font-medium text-slate-300 hover:bg-slate-800"
              >
                <RotateCcw className="h-3.5 w-3.5" />
                Reset
              </button>
            </div>

            {generateMutation.isError && (
              <div className="flex items-start gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-200">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
                <span>{(generateMutation.error as Error).message}</span>
              </div>
            )}

            {extractedCti && (
              <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-slate-200">
                    {extractedCti.threat_title}
                  </span>
                  <span className="rounded bg-sky-500/15 px-2 py-0.5 font-mono text-[11px] text-sky-300">
                    {extractedCti.logsource.product}/{extractedCti.logsource.category}
                  </span>
                </div>
                <p className="mt-1.5 text-slate-400">{extractedCti.summary}</p>
              </div>
            )}
          </section>

          {/* Right: 3-Tab Output Panel */}
          <section className="flex flex-col rounded-xl border border-slate-800 bg-slate-900/70 p-4 lg:col-span-7">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div className="inline-flex rounded-lg border border-slate-800 bg-slate-950 p-1 text-xs">
                <button
                  type="button"
                  onClick={() => setActiveTab("sigma")}
                  className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 font-medium transition ${
                    activeTab === "sigma"
                      ? "bg-sky-600 text-white"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <FileCode2 className="h-3.5 w-3.5" />
                  Sigma YAML
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("splunk")}
                  className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 font-medium transition ${
                    activeTab === "splunk"
                      ? "bg-sky-600 text-white"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Terminal className="h-3.5 w-3.5" />
                  Splunk SPL
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("sentinel")}
                  className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 font-medium transition ${
                    activeTab === "sentinel"
                      ? "bg-sky-600 text-white"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  <Shield className="h-3.5 w-3.5" />
                  Microsoft Sentinel KQL
                </button>
              </div>

              <div className="flex items-center gap-2">
                {result && (
                  <span
                    className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-medium ${
                      result.status === "success"
                        ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                        : "border-rose-500/40 bg-rose-500/10 text-rose-300"
                    }`}
                  >
                    {result.status === "success"
                      ? "pySigma Validated"
                      : "Validation Failed"}
                  </span>
                )}

                <button
                  type="button"
                  disabled={!currentOutput}
                  onClick={handleCopy}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {copiedTab === activeTab ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                      Copied
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" />
                      Copy
                    </>
                  )}
                </button>
              </div>
            </div>

            {result?.status === "failed" && result.error && (
              <div className="mb-3 rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 font-mono text-xs text-rose-200">
                {result.error}
              </div>
            )}

            <div className="relative flex-1 rounded-lg border border-slate-800 bg-slate-950">
              {currentOutput ? (
                <pre className="h-[460px] overflow-auto p-4 font-mono text-xs leading-relaxed text-emerald-200">
                  {currentOutput}
                </pre>
              ) : (
                <div className="flex h-[460px] flex-col items-center justify-center p-6 text-center text-xs text-slate-500">
                  <FileCode2 className="mb-2 h-8 w-8 text-slate-700" />
                  <p>
                    Select a preset or enter a threat report to generate and transpile a
                    validated Sigma rule.
                  </p>
                </div>
              )}
            </div>
          </section>
        </div>

        {/* TanStack Tables */}
        <ReferenceTables
          retrievedRules={retrievedRules}
          extractedCti={extractedCti}
        />
      </main>
    </div>
  );
}
