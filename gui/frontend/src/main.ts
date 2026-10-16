import "./style.css";
import { h, mount, $ } from "./dom";
import { loadLanguage, t, currentLanguage } from "./i18n";
import { call, errText, ParsedCode, Settings, State } from "./api";
import { hostView, renderHost, submitReply, loadDefaultPort } from "./host";
import { joinView, renderJoin, join, joinCodeInUse } from "./join";
import { diagView, renderDiag } from "./diag";
import { settingsView, renderSettings } from "./settings";
import { showFirewallGuide } from "./firewall";
import { loadBrand, brandInfo } from "./brand";
import { ReadClipboard, TakeLink, OpenURL, SetQuitTexts } from "../wailsjs/go/main/App";
import { EventsOn } from "../wailsjs/runtime/runtime";

type Tab = "host" | "join" | "diag" | "settings";
const renderers: Record<Tab, (s: State) => void> = { host: renderHost, join: renderJoin, diag: renderDiag, settings: renderSettings };

let tab: Tab = "host";
let state: State | null = null;
let coreError = "";
let clipboardOffer: ParsedCode | null = null;
let linkOffer = ""; // a join link that arrived while already in a world
const dismissed = new Set<string>();
const ownCodes = new Set<string>(); // every code this computer has hosted with
let lastRendered = "";
let lastRenderAt = 0;
let pointerDown = false;
let languageSetting = "";
let views: Record<Tab, HTMLElement>;

const logo = `<svg viewBox="0 0 32 32" width="28" height="28" aria-hidden="true"><rect width="32" height="32" rx="7" fill="#3f8f3a"/><rect x="5" y="17" width="22" height="10" rx="1" fill="#6b4a2b"/><rect x="5" y="13" width="22" height="5" fill="#59b84c"/><circle cx="11" cy="9" r="3" fill="#fff"/><circle cx="21" cy="9" r="3" fill="#fff"/><path d="M14 9h4" stroke="#fff" stroke-width="2"/></svg>`;

function appName() {
  const b = brandInfo();
  return currentLanguage() === "zh-CN" && b.nameZh ? `${b.nameZh} · ${b.name}` : b.name;
}

function build() {
  views = {
    host: hostView(),
    join: joinView(),
    diag: diagView(),
    settings: settingsView(async (lang) => {
      languageSetting = lang;
      await applyLanguage();
    }),
  };
  const langSelect = h(
    "select",
    { class: "lang", "aria-label": t("settings.language"), onchange: (e: Event) => setLanguage((e.target as HTMLSelectElement).value) },
    h("option", { value: "" }, t("settings.lang_auto")),
    h("option", { value: "en" }, "English"),
    h("option", { value: "zh-CN" }, "简体中文"),
  ) as HTMLSelectElement;
  langSelect.value = languageSetting;
  const nav = (["host", "join", "diag", "settings"] as Tab[]).map((k) =>
    h("button", { class: "tab" + (k === tab ? " active" : ""), "data-tab": k, onclick: () => select(k) }, t("nav." + k)),
  );
  mount(
    $("app"),
    h("header", null, h("div", { class: "brand", html: logo }), h("h1", null, appName()), h("nav", null, nav), langSelect),
    h("div", { id: "banners" }),
    h("main", null, Object.values(views)),
  );
  select(tab);
  document.title = brandInfo().name;
  void SetQuitTexts(t("quit.title"), t("quit.message"), t("quit.quit"), t("common.cancel"));
}

function select(k: Tab) {
  tab = k;
  for (const [name, el] of Object.entries(views)) el.hidden = name !== k;
  document.querySelectorAll<HTMLElement>("nav .tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === k));
  if (state) renderers[k](state);
  if (k === "host") void loadDefaultPort();
  renderBanners();
}

async function setLanguage(lang: string) {
  languageSetting = lang;
  try {
    const s = await call<Settings>("GET", "/v1/settings");
    await call("PUT", "/v1/settings", { ...s, language: lang });
  } catch {
    /* still switch the UI */
  }
  await applyLanguage();
}

async function applyLanguage() {
  await loadLanguage(languageSetting);
  build();
}

function banner(cls: string, text: string, ...actions: HTMLElement[]) {
  return h("div", { class: "banner " + cls, role: "status" }, h("span", null, text), h("span", { class: "row" }, actions));
}

function renderBanners() {
  const el = document.getElementById("banners");
  if (!el) return;
  const items: HTMLElement[] = [];
  if (coreError) items.push(banner("error", t("gui.core_unreachable", { error: coreError })));
  if (linkOffer) {
    const code = linkOffer;
    items.push(
      banner(
        "info",
        t("link.confirm_switch"),
        h("button", { class: "primary", onclick: () => { linkOffer = ""; select("join"); void join(code); } }, t("clipboard.join")),
        h("button", { class: "subtle", onclick: () => { linkOffer = ""; renderBanners(); } }, t("common.dismiss")),
      ),
    );
  }
  if (clipboardOffer) {
    const offer = clipboardOffer;
    const dismiss = h("button", { class: "subtle", onclick: () => { dismissed.add(offer.code); clipboardOffer = null; renderBanners(); } }, t("common.dismiss"));
    if (offer.kind === "invite") {
      items.push(
        banner("info", t("clipboard.invite"), h("button", { class: "primary", onclick: () => { dismissed.add(offer.code); clipboardOffer = null; select("join"); void join(offer.code); } }, t("clipboard.join")), dismiss),
      );
    } else {
      items.push(
        banner("info", t("clipboard.reply"), h("button", { class: "primary", onclick: () => { dismissed.add(offer.code); clipboardOffer = null; select("host"); void submitReply(offer.code); } }, t("clipboard.use_reply")), dismiss),
      );
    }
  }
  if (state && (state.firewall === "missing" || state.firewall === "blocked") && state.host && state.host.status !== "stopped") {
    items.push(banner("warn", t("firewall.banner_" + state.firewall), h("button", { onclick: () => showFirewallGuide(state!.firewall) }, t("firewall.show_guide"))));
  }
  const u = state?.update.result;
  if (u?.available) {
    const url = u.download?.urls?.[0] ?? u.notesUrl ?? "";
    items.push(
      banner(
        "info",
        t("update.available", { version: u.latest ?? "" }) + (u.notes ? " — " + u.notes : ""),
        h("button", { class: "primary", onclick: () => url && OpenURL(url) }, t("update.download")),
        u.notesUrl ? h("button", { class: "subtle", onclick: () => OpenURL(u.notesUrl!) }, t("update.notes")) : h("span"),
      ),
    );
  }
  mount(el, items);
}

/** True while re-rendering would get in the user's way. */
function interacting(): boolean {
  if (pointerDown) return true; // a click in progress would be lost
  const sel = window.getSelection();
  const main = document.querySelector("main");
  return !!sel && !sel.isCollapsed && !!main && !!sel.anchorNode && main.contains(sel.anchorNode); // selecting a code
}

/** A world we're joining or in: the code, normalised by the core. */
function activeJoinCode(): string {
  const j = state?.join;
  return j && !["stopped", "failed", "disconnected"].includes(j.status) ? j.code : "";
}

function forgetStaleOffers() {
  if (state?.host?.code) ownCodes.add(state.host.code);
  const code = clipboardOffer?.code;
  if (code && (ownCodes.has(code) || code === activeJoinCode() || joinCodeInUse() === code)) {
    dismissed.add(code);
    clipboardOffer = null;
  }
  if (linkOffer && linkOffer === activeJoinCode()) linkOffer = "";
}

async function poll() {
  try {
    state = await call<State>("GET", "/v1/state");
    coreError = "";
    forgetStaleOffers();
    // Rebuild only when something changed (or every 15 s for the "for 3 min"
    // timers), and never in the middle of a click or a text selection.
    const json = JSON.stringify(state);
    const due = json !== lastRendered || Date.now() - lastRenderAt > 15000;
    if (due && !interacting()) {
      renderers[tab](state);
      lastRendered = json;
      lastRenderAt = Date.now();
    }
  } catch (e) {
    coreError = errText(e);
  }
  renderBanners();
}

/** Poll once a second; the next poll starts only after this one finished. */
async function pollLoop() {
  await poll();
  window.setTimeout(() => void pollLoop(), 1000);
}

async function checkClipboard() {
  const text = await ReadClipboard();
  if (!text || !/LY1R?-/i.test(text)) return;
  try {
    const p = await call<ParsedCode>("POST", "/v1/code/parse", { text });
    if (p.expired || dismissed.has(p.code)) return;
    if (p.kind === "invite") {
      // Don't offer our own codes (old ones too) or the world we're already in.
      if (ownCodes.has(p.code) || state?.host?.code === p.code || activeJoinCode() === p.code || joinCodeInUse() === p.code) return;
    } else if (!state?.host || state.host.status === "stopped") {
      return;
    }
    clipboardOffer = p;
    renderBanners();
  } catch {
    /* not a usable code */
  }
}

async function handleLink(code: string) {
  if (!code) return;
  select("join");
  const current = activeJoinCode();
  if (current) {
    // Already joining or playing somewhere: never drop that silently.
    if (current !== code) {
      linkOffer = code;
      renderBanners();
    }
    return;
  }
  await join(code);
}

async function main() {
  await loadBrand();
  try {
    const s = await call<Settings>("GET", "/v1/settings");
    languageSetting = s.language;
  } catch (e) {
    coreError = errText(e);
  }
  await loadLanguage(languageSetting);
  build();
  window.addEventListener("pointerdown", () => (pointerDown = true), true);
  window.addEventListener("pointerup", () => window.setTimeout(() => (pointerDown = false), 0), true);
  window.addEventListener("pointercancel", () => (pointerDown = false), true);
  await pollLoop();
  window.addEventListener("focus", () => void checkClipboard());
  void checkClipboard();
  EventsOn("link", (code: string) => void handleLink(code));
  void handleLink(await TakeLink());
}

void main();
