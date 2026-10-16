import { h, mount, toast } from "./dom";
import { t, fmtTime } from "./i18n";
import { call, errText, adviceText, toApiError, Report, State } from "./api";
import { ExportLogs } from "../wailsjs/go/main/App";
import { showFirewallGuide } from "./firewall";

let dyn: HTMLElement;
let logsBox: HTMLElement;
let runBtn: HTMLButtonElement;

export function diagView(): HTMLElement {
  dyn = h("div");
  logsBox = h("pre", { class: "logs", hidden: true });
  runBtn = h("button", { class: "primary", onclick: run }, t("diag.run")) as HTMLButtonElement;
  return h(
    "div",
    { class: "view" },
    h(
      "section",
      { class: "card" },
      h("h2", null, t("diag.title")),
      h("p", { class: "lead" }, t("diag.intro")),
      h(
        "div",
        { class: "row" },
        runBtn,
        h("button", { onclick: exportLogs }, t("diag.export")),
        h("button", { class: "subtle", onclick: toggleLogs }, t("diag.show_logs")),
      ),
      h("p", { class: "muted small" }, t("diag.privacy")),
    ),
    dyn,
    logsBox,
  );
}

async function run() {
  try {
    await call("POST", "/v1/diagnostics/run");
  } catch (e) {
    toast(errText(e));
  }
}

async function exportLogs() {
  try {
    const path = await ExportLogs(t("diag.export"));
    if (path) toast(t("diag.exported", { path }));
  } catch (e) {
    toast(errText(toApiError(e)));
  }
}

async function toggleLogs() {
  if (!logsBox.hidden) {
    logsBox.hidden = true;
    return;
  }
  try {
    const res = await call<{ lines: string[] }>("GET", "/v1/logs");
    logsBox.textContent = res.lines.join("\n");
    logsBox.hidden = false;
    logsBox.scrollTop = logsBox.scrollHeight;
  } catch (e) {
    toast(errText(e));
  }
}

const yes = () => h("span", { class: "ok" }, "✔ ", t("common.yes"));
const no = () => h("span", { class: "warn" }, "✖ ", t("common.no"));

function reportTable(r: Report) {
  const pm = r.portMap?.mapping;
  const rows: [string, Node | string][] = [
    [t("diag.nat_type"), h("span", null, h("strong", null, t("nat." + r.natType)), " — ", t("nat_hint." + r.natType))],
    [t("diag.public_ip"), r.publicV4 || "—"],
    [t("diag.ipv6"), r.ipv6 ? yes() : no()],
    [t("diag.port_mapping"), pm ? h("span", { class: "ok" }, "✔ ", t("diag.port_mapping_ok", { proto: pm.protocol.toUpperCase(), addr: pm.external })) : no()],
    [t("diag.cgnat"), r.cgnat ? h("span", { class: "warn" }, "⚠ ", t(r.cgnatReason || "cgnat.local_shared")) : h("span", null, t("common.no"))],
    [t("diag.udp"), r.udpBlocked ? h("span", { class: "warn" }, "✖ ", t("diag.udp_blocked")) : yes()],
  ];
  return h(
    "table",
    { class: "kv" },
    h(
      "tbody",
      null,
      rows.map(([k, v]) => h("tr", null, h("th", null, k), h("td", null, v))),
    ),
  );
}

function stunTable(r: Report) {
  const all = [...(r.stun4 ?? []).map((x) => ({ ...x, fam: "IPv4" })), ...(r.stun6 ?? []).map((x) => ({ ...x, fam: "IPv6" }))];
  return h(
    "details",
    { "data-key": "stun" },
    h("summary", null, t("diag.stun_servers", { ok: all.filter((x) => !x.error).length, n: all.length })),
    h(
      "table",
      { class: "attempts" },
      h("thead", null, h("tr", null, h("th", null, t("diag.server")), h("th", null, ""), h("th", null, t("diag.result")), h("th", null, "RTT"))),
      h(
        "tbody",
        null,
        all.map((x) =>
          h(
            "tr",
            null,
            h("td", null, x.server),
            h("td", null, x.fam),
            h("td", { class: x.error ? "warn" : "ok" }, x.error ? x.error : x.mapped ?? ""),
            h("td", null, x.error ? "" : `${x.rttMs} ms`),
          ),
        ),
      ),
    ),
  );
}

function firewallLine(status: string) {
  if (status === "not_applicable") return null;
  const bad = status === "missing" || status === "blocked";
  return h(
    "section",
    { class: "card" + (bad ? " warn-card" : "") },
    h("h3", null, t("firewall.title")),
    h("p", null, t("firewall." + status)),
    bad ? h("button", { onclick: () => showFirewallGuide(status) }, t("firewall.show_guide")) : null,
  );
}

export function renderDiag(state: State) {
  const d = state.diagnostics;
  runBtn.disabled = d.running;
  runBtn.textContent = d.running ? t("diag.running") : t("diag.run");
  const r = d.report ?? state.host?.report ?? state.join?.report ?? null;
  const outlook = d.outlook ?? state.host?.outlook ?? null;
  mount(
    dyn,
    firewallLine(state.firewall),
    r
      ? h(
          "section",
          { class: "card" },
          h("div", { class: "row spread" }, h("h3", null, t("diag.results")), h("span", { class: "muted small" }, fmtTime(r.time))),
          outlook ? h("p", { class: "lead" }, adviceText(outlook.summary)) : null,
          outlook?.advice?.map((a) => h("p", { class: "muted" }, adviceText(a))),
          reportTable(r),
          stunTable(r),
        )
      : h("section", { class: "card" }, h("p", { class: "muted" }, d.running ? t("diag.running") : t("diag.no_results"))),
  );
}
