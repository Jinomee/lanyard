import { Call } from "../wailsjs/go/main/App";
import { t } from "./i18n";

// ---- Types mirroring the core's JSON (internal/engine, internal/connect) ----

export interface Advice {
  key: string;
  params?: Record<string, string>;
}
export interface Diagnosis {
  summary: Advice;
  advice: Advice[] | null;
}
export interface StunResult {
  server: string;
  resolved?: string;
  mapped?: string;
  other?: string;
  rttMs?: number;
  error?: string;
}
export interface Report {
  time: string;
  elapsedMs: number;
  local: { globalV6?: string[]; lanV4?: string; allV4?: string[] };
  ipv6: boolean;
  ipv6Stun: string;
  stun4: StunResult[] | null;
  stun6?: StunResult[] | null;
  publicV4?: string;
  mapping: string;
  filtering: string;
  natType: string;
  portMap: { mapping?: { protocol: string; external: string } | null; errors?: Record<string, string> | null };
  cgnat: boolean;
  cgnatReason?: string;
  udpBlocked: boolean;
}
export interface World {
  motd: string;
  port: number;
  source: string;
  local: boolean;
}
export interface GuestInfo {
  id: string;
  name: string;
  addr: string;
  since: string;
}
export interface PunchInfo {
  id: string;
  started: string;
  targets: string[];
  active: boolean;
}
export interface UserError {
  key: string;
  params?: Record<string, string>;
  detail?: string;
}
export interface HostState {
  status: "starting" | "ready" | "refreshing" | "error" | "stopped";
  error?: UserError | null;
  mode: "auto" | "manual";
  manualPort: number;
  worlds: World[];
  lanDetection: boolean;
  target?: string;
  targetMotd?: string;
  targetOk: boolean;
  code?: string;
  link?: string;
  expires?: string;
  approval: boolean;
  guests: GuestInfo[];
  pending: GuestInfo[];
  punches: PunchInfo[];
  report?: Report | null;
  outlook?: Diagnosis | null;
  udpPort: number;
  bytesUp: number;
  bytesDown: number;
  since: string;
}
export interface Attempt {
  strategy: string;
  addr: string;
  phase: string;
  started: string;
  durationMs: number;
  tries: number;
  outcome: string;
  error?: string;
}
export interface JoinState {
  status: "connecting" | "need_reply" | "authenticating" | "waiting_approval" | "connected" | "failed" | "disconnected" | "stopped";
  phase: string;
  code: string;
  host: { ipv6: boolean; portMapped: boolean; mapping: string; cgnat: boolean; approval: boolean; dedicated: boolean; expires: string };
  replyCode?: string;
  replyExpires?: string;
  attempts: Attempt[] | null;
  via?: Attempt | null;
  localAddr?: string;
  motd?: string;
  failure?: Diagnosis | null;
  report?: Report | null;
  since: string;
  connectedAt?: string;
  bytesUp: number;
  bytesDown: number;
}
export interface UpdateResult {
  checked: string;
  current: string;
  latest?: string;
  available: boolean;
  source?: string;
  notesUrl?: string;
  notes?: string;
  download?: { name: string; urls: string[]; sha256: string } | null;
  error?: string;
}
export interface State {
  app: { name: string; version: string; os: string; apiVersion: number };
  host?: HostState | null;
  join?: JoinState | null;
  diagnostics: { running: boolean; report?: Report | null; outlook?: Diagnosis | null };
  update: { enabled: boolean; configured: boolean; checking: boolean; result?: UpdateResult | null };
  firewall: string;
}
export interface Settings {
  language: string;
  playerName: string;
  stunServers: string[];
  upnp: boolean;
  udpPort: number;
  guestPort: number;
  manualPort: number;
  requireApproval: boolean;
  inviteHours: number;
  updateChecks: boolean;
  relayAddress: string;
}
export interface ParsedCode {
  kind: "invite" | "reply";
  code: string;
  expires: string;
  expired: boolean;
}

export class ApiError extends Error {
  constructor(public err: UserError) {
    super(err.key);
  }
}

/** Turn an error from a Go binding (JSON-encoded UserError) into an ApiError. */
export function toApiError(e: unknown): ApiError {
  if (e instanceof ApiError) return e;
  let ue: UserError = { key: "gui.err.core", detail: String(e) };
  try {
    const parsed = JSON.parse(String(e));
    if (parsed && typeof parsed.key === "string") ue = parsed;
  } catch {
    /* not JSON */
  }
  return new ApiError(ue);
}

/** Call the core's control API (via the Go side). Errors become ApiError. */
export async function call<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  try {
    return (await Call(method, path, body ?? null)) as T;
  } catch (e) {
    throw toApiError(e);
  }
}

/** Human text for any error. */
export function errText(e: unknown): string {
  if (e instanceof ApiError) {
    const msg = t(e.err.key, e.err.params);
    return msg === e.err.key && e.err.detail ? `${msg} (${e.err.detail})` : msg;
  }
  return String(e);
}

/** Human text for an advice item. */
export function adviceText(a: Advice): string {
  return t(a.key, a.params);
}
