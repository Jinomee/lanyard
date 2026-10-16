import { h, mount, toast } from "./dom";
import { t, fmtTime, fmtBytes, fmtDuration } from "./i18n";
import { call, errText, adviceText, HostState, Settings, State } from "./api";
import { CopyText } from "../wailsjs/go/main/App";
import { maybeShowFirewallGuide } from "./firewall";

let root: HTMLElement;
let idle: HTMLElement;
let active: HTMLElement;
let dyn: HTMLElement;
let msg: HTMLElement;
let replyInput: HTMLInputElement;
let replyMsg: HTMLElement;
let portInput: HTMLInputElement;
let modeAuto: HTMLInputElement;
let modeManual: HTMLInputElement;
let lastState: State | null = null;
let portEdited = false; // the user typed a port: settings must not overwrite it
let typedPort = "";

export function hostView(): HTMLElement {
  modeAuto = h("input", { type: "radio", name: "mode", value: "auto", checked: true }) as HTMLInputElement;
  modeManual = h("input", { type: "radio", name: "mode", value: "manual" }) as HTMLInputElement;
  portInput = h("input", {
    type: "number",
    min: 1,
    max: 65535,
    // Views are rebuilt on a language change: keep what was typed.
    value: portEdited ? typedPort : 25565,
    class: "port",
    "aria-label": t("host.manual_port"),
    oninput: () => {
      portEdited = true;
      typedPort = portInput.value;
    },
  }) as HTMLInputElement;
  void loadDefaultPort();
  msg = h("p", { class: "error", role: "alert" });

  idle = h(
    "section",
    { class: "card" },
    h("h2", null, t("host.title")),
    h("p", { class: "lead" }, t("host.intro")),
    h(
      "ol",
      { class: "steps" },
      h("li", null, t("host.step_open_lan")),
      h("li", null, t("host.step_start")),
      h("li", null, t("host.step_send_code")),
    ),
    h(
      "fieldset",
      { class: "choices" },
      h("legend", null, t("host.what")),
      h("label", { class: "choice" }, modeAuto, h("span", null, h("strong", null, t("host.mode_auto")), h("small", null, t("host.mode_auto_hint")))),
      h(
        "label",
        { class: "choice" },
        modeManual,
        h("span", null, h("strong", null, t("host.mode_manual")), h("small", null, t("host.mode_manual_hint"))),
        portInput,
      ),
    ),
    h("button", { class: "primary big", onclick: start }, t("host.start")),
    msg,
  );

  replyInput = h("input", { type: "text", placeholder: "LY1R-…", spellcheck: "false", autocomplete: "off", class: "code-input" }) as HTMLInputElement;
  replyMsg = h("p", { class: "error", role: "alert" });
  dyn = h("div");
  active = h(
    "div",
    null,
    dyn,
    h(
      "section",
      { class: "card" },
      h("h3", null, t("host.reply_title")),
      h("p", { class: "muted" }, t("host.reply_hint")),
      h("div", { class: "row" }, replyInput, h("button", { class: "primary", onclick: submitReply }, t("host.reply_submit"))),
      replyMsg,
    ),
    h("div", { class: "row end" }, h("button", { class: "danger", onclick: stop }, t("host.stop"))),
  );
  root = h("div", { class: "view" }, idle, active);
  return root;
}

/** Fill in the "default server port" setting unless the user typed a port. */
export async function loadDefaultPort() {
  if (portEdited) return;
  try {
    const s = await call<Settings>("GET", "/v1/settings");
    if (!portEdited && s.manualPort) portInput.value = String(s.manualPort);
  } catch {
    /* keep the current value */
  }
}

async function start() {
  msg.textContent = "";
  const manual = modeManual.checked;
  try {
    await call("POST", "/v1/host/start", { mode: manual ? "manual" : "auto", manualPort: manual ? Number(portInput.value) : 0 });
    maybeShowFirewallGuide(lastState?.firewall ?? "");
  } catch (e) {
    msg.textContent = errText(e);
  }
}

async function stop() {
  await call("POST", "/v1/host/stop").catch(() => undefined);
}

export async function submitReply(code?: string) {
  replyMsg.textContent = "";
  const value = (typeof code === "string" ? code : replyInput.value).trim();
  if (!value) return;
  try {
    await call("POST", "/v1/host/reply", { code: value });
    replyInput.value = "";
    toast(t("host.reply_accepted"));
  } catch (e) {
    replyMsg.textContent = errText(e);
  }
}

async function copy(text: string, done: string) {
  if (await CopyText(text)) toast(done);
}

function hosting(s: HostState | null | undefined): s is HostState {
  return !!s && s.status !== "stopped";
}

export function renderHost(state: State) {
  lastState = state;
  const s = state.host;
  idle.hidden = hosting(s) && s.status !== "error";
  active.hidden = !hosting(s) || s.status === "error";
  if (s?.status === "error") {
    msg.textContent = t("host.failed") + " " + (s.error ? t(s.error.key) : "");
  }
  if (!hosting(s) || s.status === "error") return;
  mount(dyn, statusCard(s), codeCard(s), peopleCard(s));
}

function statusCard(s: HostState) {
  let world: HTMLElement;
  if (s.mode === "manual") {
    world = s.targetOk
      ? h("p", { class: "ok" }, "✔ ", t("host.server_found", { port: s.manualPort }))
      : h("p", { class: "warn" }, "⚠ ", t("host.server_missing", { port: s.manualPort }));
  } else if (s.target) {
    world = h("p", { class: "ok" }, "✔ ", t("host.world_found", { motd: s.targetMotd || "?" }));
  } else if (!s.lanDetection) {
    world = h("p", { class: "warn" }, "⚠ ", t("host.lan_detection_off"));
  } else {
    world = h("div", { class: "warn" }, h("p", null, "⏳ ", t("host.world_waiting")), h("p", { class: "muted" }, t("host.world_waiting_hint")));
  }
  const outlook = s.outlook;
  return h(
    "section",
    { class: "card" },
    h("div", { class: "row spread" }, h("h2", null, t("host.hosting")), h("span", { class: "pill" }, t("host.since", { d: fmtDuration(s.since) }))),
    world,
    s.status === "starting" || s.status === "refreshing"
      ? [
          h("p", { class: "muted" }, "⏳ ", t("host.checking_network")),
          // A renewal that keeps failing (network down): friends already
          // playing stay connected while it retries.
          s.error ? h("p", { class: "warn" }, "⚠ ", t(s.error.key)) : null,
        ]
      : outlook
        ? h(
            "div",
            { class: "outlook" },
            h("p", null, adviceText(outlook.summary)),
            (outlook.advice ?? []).map((a) => h("p", { class: "muted" }, adviceText(a))),
          )
        : null,
  );
}

function codeCard(s: HostState) {
  if (!s.code) return null;
  return h(
    "section",
    { class: "card" },
    h("h3", null, t("host.code_title")),
    h("p", { class: "muted" }, t("host.code_hint")),
    h("div", { class: "code-box", title: s.code }, s.code),
    h(
      "div",
      { class: "row" },
      h("button", { class: "primary", onclick: () => copy(s.code!, t("common.copied")) }, t("host.copy_code")),
      h("button", { onclick: () => copy(s.link!, t("common.copied")) }, t("host.copy_link")),
      h("button", { class: "subtle", onclick: () => call("POST", "/v1/host/code/new").catch(() => undefined) }, t("host.new_code")),
    ),
    h("p", { class: "muted small" }, t("host.code_expires", { time: fmtTime(s.expires) }), " · ", t("host.new_code_hint")),
    s.approval ? h("p", { class: "muted small" }, t("host.approval_on")) : null,
  );
}

function peopleCard(s: HostState) {
  const pending = s.pending.map((g) =>
    h(
      "li",
      { class: "pending" },
      h("span", null, t("host.wants_to_join", { name: g.name })),
      h(
        "span",
        { class: "row" },
        h("button", { class: "primary", onclick: () => call("POST", "/v1/host/approve", { id: g.id, allow: true }) }, t("host.allow")),
        h("button", { class: "danger", onclick: () => call("POST", "/v1/host/approve", { id: g.id, allow: false }) }, t("host.deny")),
      ),
    ),
  );
  const guests = s.guests.map((g) =>
    h(
      "li",
      null,
      h("span", null, h("strong", null, g.name), " ", h("small", { class: "muted" }, t("host.connected_for", { d: fmtDuration(g.since) }))),
      h("button", { class: "subtle", onclick: () => call("POST", "/v1/host/kick", { id: g.id }) }, t("host.kick")),
    ),
  );
  const punches = s.punches
    .filter((p) => p.active)
    .map((p) => h("li", null, "⏳ ", t("host.punching", { n: p.targets.length })));
  return h(
    "section",
    { class: "card" },
    h("h3", null, t("host.players", { n: s.guests.length })),
    pending.length || guests.length || punches.length
      ? h("ul", { class: "people" }, pending, punches, guests)
      : h("p", { class: "muted" }, t("host.no_players")),
    h("p", { class: "muted small" }, t("common.traffic", { up: fmtBytes(s.bytesUp), down: fmtBytes(s.bytesDown) })),
  );
}
