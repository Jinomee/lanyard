import { h, mount, toast } from "./dom";
import { t, fmtTime, fmtBytes, fmtDuration } from "./i18n";
import { call, errText, adviceText, JoinState, State, Attempt } from "./api";
import { CopyText } from "../wailsjs/go/main/App";

let codeInput: HTMLInputElement;
let msg: HTMLElement;
let dyn: HTMLElement;
let lastCode = "";

export function joinView(): HTMLElement {
  codeInput = h("input", {
    type: "text",
    placeholder: "LY1-…",
    spellcheck: "false",
    autocomplete: "off",
    class: "code-input",
    "aria-label": t("join.code_label"),
    onkeydown: (e: KeyboardEvent) => {
      if (e.key === "Enter") join();
    },
  }) as HTMLInputElement;
  msg = h("p", { class: "error", role: "alert" });
  dyn = h("div");
  return h(
    "div",
    { class: "view" },
    h(
      "section",
      { class: "card" },
      h("h2", null, t("join.title")),
      h("p", { class: "lead" }, t("join.intro")),
      h("div", { class: "row" }, codeInput, h("button", { class: "primary", onclick: () => join() }, t("join.join"))),
      msg,
    ),
    dyn,
  );
}

/** Join with a code (from the input, a link, or the clipboard banner). */
export async function join(code?: string) {
  msg.textContent = "";
  const value = (code ?? codeInput.value).trim();
  if (!value) return;
  codeInput.value = value;
  try {
    await call("POST", "/v1/join/start", { code: value });
    lastCode = value;
  } catch (e) {
    msg.textContent = errText(e);
  }
}

export function joinCodeInUse() {
  return lastCode;
}

async function leave() {
  await call("POST", "/v1/join/stop").catch(() => undefined);
}

async function copy(text: string) {
  if (await CopyText(text)) toast(t("common.copied"));
}

export function renderJoin(state: State) {
  const j = state.join;
  if (!j || j.status === "stopped") {
    mount(dyn);
    return;
  }
  if (!lastCode) lastCode = j.code;
  mount(dyn, statusCard(j), attemptsCard(j));
}

function statusCard(j: JoinState) {
  switch (j.status) {
    case "connecting":
    case "authenticating":
      return h(
        "section",
        { class: "card" },
        h("h3", null, "⏳ ", t(j.status === "connecting" ? "join.connecting" : "join.authenticating")),
        h("p", { class: "muted" }, t("join.connecting_hint")),
        h("div", { class: "row end" }, h("button", { onclick: leave }, t("common.cancel"))),
      );
    case "need_reply":
      return h(
        "section",
        { class: "card highlight" },
        h("h3", null, t("join.need_reply_title")),
        h("p", null, t("join.need_reply_text")),
        j.replyCode
          ? [
              h("div", { class: "code-box" }, j.replyCode),
              h("div", { class: "row" }, h("button", { class: "primary", onclick: () => copy(j.replyCode!) }, t("join.copy_reply"))),
              h("p", { class: "muted small" }, t("join.reply_valid_until", { time: fmtTime(j.replyExpires) }), " · ", t("join.still_trying")),
            ]
          : h("p", { class: "muted" }, "⏳ ", t("join.preparing_reply")),
        h("div", { class: "row end" }, h("button", { onclick: leave }, t("common.cancel"))),
      );
    case "waiting_approval":
      return h(
        "section",
        { class: "card" },
        h("h3", null, "⏳ ", t("join.waiting_approval")),
        h("p", { class: "muted" }, t("join.waiting_approval_hint")),
        h("div", { class: "row end" }, h("button", { onclick: leave }, t("common.cancel"))),
      );
    case "connected":
      return h(
        "section",
        { class: "card success" },
        h("h3", null, "✔ ", t("join.connected")),
        h("p", null, t("join.connected_lan", { motd: j.motd || "" })),
        h("p", { class: "muted" }, t("join.connected_direct")),
        h("div", { class: "row" }, h("code", { class: "addr" }, j.localAddr ?? ""), h("button", { onclick: () => copy(j.localAddr ?? "") }, t("join.copy_address"))),
        h(
          "p",
          { class: "muted small" },
          j.via ? t("join.via", { how: t("strategy." + j.via.strategy) }) + " · " : "",
          t("join.connected_for", { d: fmtDuration(j.connectedAt) }),
          " · ",
          t("common.traffic", { up: fmtBytes(j.bytesUp), down: fmtBytes(j.bytesDown) }),
        ),
        h("p", { class: "muted small" }, t("join.auth_note")),
        h("div", { class: "row end" }, h("button", { class: "danger", onclick: leave }, t("join.leave"))),
      );
    case "failed":
    case "disconnected": {
      const d = j.failure;
      return h(
        "section",
        { class: "card failure" },
        h("h3", null, d ? adviceText(d.summary) : t("join.failed")),
        d && d.advice && d.advice.length
          ? [h("p", null, t("join.what_to_try")), h("ol", { class: "advice" }, d.advice.map((a) => h("li", null, adviceText(a))))]
          : null,
        h(
          "div",
          { class: "row" },
          h("button", { class: "primary", onclick: () => join(j.code) }, t(j.status === "failed" ? "join.try_again" : "join.reconnect")),
          h("button", { onclick: leave }, t("common.close")),
        ),
      );
    }
  }
  return null;
}

function attemptRow(a: Attempt) {
  const cls = a.outcome === "ok" ? "ok" : a.outcome === "pending" ? "muted" : "warn";
  return h(
    "tr",
    null,
    h("td", null, t("strategy." + a.strategy)),
    h("td", null, h("code", null, a.addr)),
    h("td", null, t("phase." + a.phase)),
    h("td", { class: cls }, t("outcome." + a.outcome)),
    h("td", null, String(a.tries)),
  );
}

function attemptsCard(j: JoinState) {
  const as = j.attempts ?? [];
  if (!as.length) return null;
  return h(
    "details",
    { class: "card", open: j.status === "failed" ? true : undefined },
    h("summary", null, t("join.attempts_title", { n: as.length })),
    h(
      "table",
      { class: "attempts" },
      h(
        "thead",
        null,
        h("tr", null, h("th", null, t("attempt.strategy")), h("th", null, t("attempt.addr")), h("th", null, t("attempt.phase")), h("th", null, t("attempt.outcome")), h("th", null, t("attempt.tries"))),
      ),
      h("tbody", null, as.map(attemptRow)),
    ),
    j.report ? h("p", { class: "muted small" }, t("diag.your_nat", { type: t("nat." + j.report.natType) })) : null,
  );
}

export function setJoinError(e: unknown) {
  msg.textContent = errText(e);
}
