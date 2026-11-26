import type {
  GenerateRequestPayload,
  GenerateResponsePayload,
  StreamProgressEvent,
} from "../types";

export const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000"
).replace(/\/$/, "");

export async function checkBackendHealth(): Promise<{ status: string }> {
  const response = await fetch(`${API_BASE_URL}/health`);
  if (!response.ok) {
    throw new Error(`Health check failed (${response.status})`);
  }
  return response.json() as Promise<{ status: string }>;
}

interface StreamCallbacks {
  onProgress: (event: StreamProgressEvent) => void;
  onComplete: (result: GenerateResponsePayload) => void;
}

export async function streamGenerateSigma(
  payload: GenerateRequestPayload,
  callbacks: StreamCallbacks,
  signal?: AbortSignal
): Promise<GenerateResponsePayload> {
  const response = await fetch(`${API_BASE_URL}/api/v1/generate/stream`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "text/event-stream",
    },
    body: JSON.stringify(payload),
    signal,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(errorText || `Request failed with status ${response.status}`);
  }

  if (!response.body) {
    throw new Error("Streaming response body is unavailable.");
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let finalResult: GenerateResponsePayload | null = null;

  const processBlock = (rawBlock: string) => {
    const block = rawBlock.trim();
    if (!block) return;

    let eventName = "message";
    const dataLines: string[] = [];

    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith("event:")) {
        eventName = line.slice(6).trim();
      } else if (line.startsWith("data:")) {
        dataLines.push(line.slice(5).trim());
      }
    }

    if (dataLines.length === 0) return;
    const parsed = JSON.parse(dataLines.join("\n"));

    if (eventName === "progress") {
      callbacks.onProgress(parsed as StreamProgressEvent);
    } else if (eventName === "complete") {
      finalResult = parsed as GenerateResponsePayload;
      callbacks.onComplete(finalResult);
    } else if (eventName === "error") {
      throw new Error(parsed.error || "Pipeline error occurred.");
    }
  };

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const parts = buffer.split(/\r?\n\r?\n/);
    buffer = parts.pop() ?? "";
    for (const part of parts) {
      processBlock(part);
    }
  }

  if (buffer.trim()) {
    processBlock(buffer);
  }

  if (!finalResult) {
    throw new Error("Stream ended before receiving a final completion event.");
  }

  return finalResult;
}
