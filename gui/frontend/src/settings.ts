import { h, mount, toast } from "./dom";
import { t } from "./i18n";
import { call, errText, Settings, State } from "./api";
import { OpenURL } from "../wailsjs/go/main/App";
import { brandInfo } from "./brand";

let form: HTMLElement;
let msg: HTMLElement;
let current: Settings | null = null;
let onLanguageChange: (lang: string) => void = () => undefined;

export function settingsView(languageChanged: (lang: string) => void): HTMLElement {
  onLanguageChange = languageChanged;
  form = h("div");
  msg = h("p", { class: "error", role: "alert" });
  const view = h("div", { class: "view" }, form, msg, aboutCard());
  void load();
  return view;
}

async function load() {
  try {
    current = await call<Settings>("GET", "/v1/settings");
    renderForm(current);
  } catch (e) {
    msg.textContent = errText(e);
  }
}

function field(label: string, input: HTMLElement, hint?: string) {
  return h("label", { class: "field" }, h("span", { class: "label" }, label), input, hint ? h("small", { class: "muted" }, hint) : null);
}

function check(label: string, el: HTMLInputElement, hint?: string) {
  return h("label", { class: "check" }, el, h("span", null, label, hint ? h("small", { class: "muted" }, hint) : null));
}

function renderForm(s: Settings) {
  const name = h("input", { type: "text", value: s.playerName, maxlength: 32 }) as HTMLInputElement;
  const lang = h(
    "select",
    null,
    h("option", { value: "" }, t("settings.lang_auto")),
    h("option", { value: "en" }, "English"),
    h("option", { value: "zh-CN" }, "简体中文"),
  ) as HTMLSelectElement;
  lang.value = s.language;
  const approval = h("input", { type: "checkbox", checked: s.requireApproval }) as HTMLInputElement;
  const hours = h("input", { type: "number", min: 1, max: 720, value: s.inviteHours }) as HTMLInputElement;
  const upnp = h("input", { type: "checkbox", checked: s.upnp }) as HTMLInputElement;
  const updates = h("input", { type: "checkbox", checked: s.updateChecks }) as HTMLInputElement;
  const manualPort = h("input", { type: "number", min: 1, max: 65535, value: s.manualPort }) as HTMLInputElement;
  const udpPort = h("input", { type: "number", min: 0, max: 65535, value: s.udpPort }) as HTMLInputElement;
  const guestPort = h("input", { type: "number", min: 0, max: 65535, value: s.guestPort }) as HTMLInputElement;
  const stun = h("textarea", { rows: 6, spellcheck: "false" }) as HTMLTextAreaElement;
  stun.value = s.stunServers.join("\n");

  const save = async () => {
    msg.textContent = "";
    const next: Settings = {
      ...s,
      playerName: name.value,
      language: lang.value,
      requireApproval: approval.checked,
      inviteHours: Number(hours.value),
      upnp: upnp.checked,
      updateChecks: updates.checked,
      manualPort: Number(manualPort.value),
      udpPort: Number(udpPort.value),
      guestPort: Number(guestPort.value),
      stunServers: stun.value.split(/\s+/).filter(Boolean),
    };
    try {
      const saved = await call<Settings>("PUT", "/v1/settings", next);
      const langChanged = saved.language !== current?.language;
      current = saved;
      toast(t("settings.saved"));
      if (langChanged) onLanguageChange(saved.language);
    } catch (e) {
      msg.textContent = errText(e);
    }
  };
  const restoreStun = async () => {
    const d = await call<Settings>("GET", "/v1/settings/defaults");
    stun.value = d.stunServers.join("\n");
  };
  const resetIdentity = async () => {
    if (!confirm(t("settings.reset_identity_confirm"))) return;
    try {
      await call("POST", "/v1/identity/reset");
      toast(t("settings.reset_identity_done"));
    } catch (e) {
      msg.textContent = errText(e);
    }
  };

  mount(
    form,
    h(
      "section",
      { class: "card" },
      h("h2", null, t("settings.title")),
      field(t("settings.player_name"), name, t("settings.player_name_hint")),
      field(t("settings.language"), lang),
      check(t("settings.approval"), approval, t("settings.approval_hint")),
      field(t("settings.invite_hours"), hours),
      check(t("settings.updates"), updates, t("settings.updates_hint")),
    ),
    h(
      "details",
      { class: "card" },
      h("summary", null, t("settings.advanced")),
      check(t("settings.upnp"), upnp, t("settings.upnp_hint")),
      field(t("settings.manual_port"), manualPort, t("settings.manual_port_hint")),
      field(t("settings.udp_port"), udpPort, t("settings.udp_port_hint")),
      field(t("settings.guest_port"), guestPort, t("settings.guest_port_hint")),
      field(t("settings.stun"), stun, t("settings.stun_hint")),
      h("div", { class: "row" }, h("button", { class: "subtle", onclick: restoreStun }, t("settings.stun_restore"))),
      h("p", { class: "muted small" }, t("settings.relay_future")),
      h("div", { class: "row" }, h("button", { class: "danger subtle", onclick: resetIdentity }, t("settings.reset_identity"))),
    ),
    h("div", { class: "row end" }, h("button", { class: "primary", onclick: save }, t("settings.save"))),
  );
}

function aboutCard() {
  const b = brandInfo();
  return h(
    "section",
    { class: "card" },
    h("h3", null, t("about.title", { app: b.name, version: b.version })),
    h("p", { class: "muted" }, t("about.text")),
    h("p", { class: "muted" }, t("about.privacy")),
    h("p", { class: "muted" }, t("about.license")),
    h("div", { class: "row" }, h("button", { class: "subtle", onclick: () => OpenURL("https://github.com/" + b.repo) }, t("about.source"))),
  );
}

export function renderSettings(_state: State) {
  /* settings are edited, not live */
}
