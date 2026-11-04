/**
 * Same-origin API client.
 *
 * - No credentials or keys are ever read from localStorage; the browser session is
 *   an HttpOnly `__Host-` cookie and the CSRF token is held in memory only.
 * - Every mutation sends an Idempotency-Key and the in-memory CSRF token.
 * - Server error bodies are rendered as safe Problems, never as raw HTML.
 */
import type { Problem } from "./types";

export class ApiError extends Error {
  readonly problem: Problem;

  constructor(problem: Problem) {
    super(problem.detail || problem.title || "Request failed");
    this.problem = problem;
  }
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export function newIdempotencyKey(): string {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi?.randomUUID) {
    throw new Error("This browser cannot generate idempotency keys.");
  }
  return cryptoApi.randomUUID();
}

interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  body?: unknown;
  headers?: Record<string, string>;
  projectId?: string;
  mutation?: boolean;
}

async function toProblem(response: Response): Promise<Problem> {
  const fallback: Problem = {
    type: "about:blank",
    title: response.statusText || "Request failed",
    status: response.status,
    code: "unexpected_response",
    detail: "The server returned an error without a Problem document.",
  };
  try {
    const parsed = (await response.json()) as Partial<Problem>;
    return { ...fallback, ...parsed };
  } catch {
    return fallback;
  }
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json", ...options.headers };
  if (options.projectId) headers["X-Project-ID"] = options.projectId;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (options.mutation ?? method !== "GET") {
    headers["Idempotency-Key"] = newIdempotencyKey();
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  }
  const response = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (response.status === 204) return undefined as T;
  if (!response.ok) throw new ApiError(await toProblem(response));
  if (response.status === 202 || response.headers.get("content-type")?.includes("json")) {
    return (await response.json()) as T;
  }
  return undefined as T;
}

export async function requestWithEtag<T>(
  path: string,
  etag: string,
  options: RequestOptions,
): Promise<T> {
  return request<T>(path, { ...options, headers: { ...options.headers, "If-Match": etag } });
}

/** Upload bytes straight to the API (same origin); the URL comes from the server. */
export async function putBytes(putPath: string, file: File, projectId: string): Promise<void> {
  const response = await fetch(putPath, {
    method: "PUT",
    headers: {
      "Content-Type": "application/zip",
      "X-Project-ID": projectId,
      "Idempotency-Key": newIdempotencyKey(),
      ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
    },
    credentials: "same-origin",
    body: file,
  });
  if (!response.ok) throw new ApiError(await toProblem(response));
}

export async function sha256Hex(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
