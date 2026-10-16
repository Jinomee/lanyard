import { h } from "./dom";
import { t } from "./i18n";
import { OpenFirewallSettings } from "../wailsjs/go/main/App";

let shownThisSession = false;

/** Show the guide automatically once, when hosting starts and no rule exists. */
export function maybeShowFirewallGuide(status: string) {
  if (shownThisSession || (status !== "missing" && status !== "blocked")) return;
  shownThisSession = true;
  showFirewallGuide(status);
}

// A simplified drawing of the Windows Defender Firewall prompt (not a
// screenshot): which boxes to tick and which button to press.
function illustration(): HTMLElement {
  const svg = `
<svg viewBox="0 0 420 250" width="100%" role="img" aria-label="${t("firewall.illustration_alt")}" xmlns="http://www.w3.org/2000/svg">
  <rect x="1" y="1" width="418" height="248" rx="6" fill="#fff" stroke="#9aa3ad"/>
  <rect x="1" y="1" width="418" height="30" rx="6" fill="#e9edf2"/>
  <text x="14" y="21" font-size="13" font-family="Segoe UI, sans-serif" fill="#1d2733">Windows Security Alert</text>
  <circle cx="34" cy="62" r="16" fill="#1f6fd1"/><path d="M27 62 l5 5 l9 -11" stroke="#fff" stroke-width="3" fill="none"/>
  <text x="60" y="58" font-size="12" font-family="Segoe UI, sans-serif" fill="#1d2733">Windows Defender Firewall has blocked some</text>
  <text x="60" y="74" font-size="12" font-family="Segoe UI, sans-serif" fill="#1d2733">features of this app</text>
  <rect x="24" y="104" width="14" height="14" rx="2" fill="#1f6fd1"/><path d="M27 111 l3 3 l6 -7" stroke="#fff" stroke-width="2" fill="none"/>
  <text x="46" y="116" font-size="12" font-family="Segoe UI, sans-serif" fill="#1d2733">Private networks, such as my home or work network</text>
  <rect x="24" y="128" width="14" height="14" rx="2" fill="#1f6fd1"/><path d="M27 135 l3 3 l6 -7" stroke="#fff" stroke-width="2" fill="none"/>
  <text x="46" y="140" font-size="12" font-family="Segoe UI, sans-serif" fill="#1d2733">Public networks, such as those in airports and cafés</text>
  <rect x="190" y="196" width="112" height="30" rx="4" fill="#1f6fd1" stroke="#f0a400" stroke-width="3"/>
  <text x="246" y="216" font-size="12" text-anchor="middle" font-family="Segoe UI, sans-serif" fill="#fff">Allow access</text>
  <rect x="312" y="196" width="90" height="30" rx="4" fill="#fff" stroke="#9aa3ad"/>
  <text x="357" y="216" font-size="12" text-anchor="middle" font-family="Segoe UI, sans-serif" fill="#1d2733">Cancel</text>
  <text x="246" y="246" font-size="11" text-anchor="middle" font-family="Segoe UI, sans-serif" fill="#b36b00">▲ ${t("firewall.click_here")}</text>
</svg>`;
  return h("div", { class: "illustration", html: svg });
}

export function showFirewallGuide(status: string) {
  const close = () => dialog.remove();
  const blocked = status === "blocked";
  const dialog = h(
    "div",
    { class: "modal-backdrop", onclick: (e: Event) => e.target === dialog && close() },
    h(
      "div",
      { class: "modal", role: "dialog", "aria-modal": "true" },
      h("h2", null, t(blocked ? "firewall.guide_blocked_title" : "firewall.guide_title")),
      blocked
        ? [
            h("p", null, t("firewall.guide_blocked_text")),
            h("ol", null, h("li", null, t("firewall.blocked_step1")), h("li", null, t("firewall.blocked_step2")), h("li", null, t("firewall.blocked_step3"))),
          ]
        : [
            h("p", null, t("firewall.guide_text")),
            illustration(),
            h("ol", null, h("li", null, t("firewall.step1")), h("li", null, t("firewall.step2")), h("li", null, t("firewall.step3"))),
          ],
      h("p", { class: "muted small" }, t("firewall.installer_note")),
      h(
        "div",
        { class: "row end" },
        h("button", { onclick: () => OpenFirewallSettings() }, t("firewall.open_settings")),
        h("button", { class: "primary", onclick: close }, t("common.ok")),
      ),
    ),
  );
  document.body.appendChild(dialog);
}
