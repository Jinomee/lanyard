import { Translations, MatchLanguage } from "../wailsjs/go/main/App";

let catalog: Record<string, string> = {};
let lang = "en";

/** Load the catalog for a setting ("" = follow the system language). */
export async function loadLanguage(setting: string) {
  lang = setting || (await MatchLanguage(navigator.language || "en"));
  catalog = await Translations(lang);
  document.documentElement.lang = lang;
}

export function currentLanguage() {
  return lang;
}

/** Translate key, replacing {name} placeholders. Missing keys show the key. */
export function t(key: string, params?: Record<string, string | number> | null): string {
  let s = catalog[key] ?? key;
  if (params) {
    for (const [k, v] of Object.entries(params)) s = s.split("{" + k + "}").join(String(v));
  }
  return s;
}

export function has(key: string) {
  return key in catalog;
}

export function fmtTime(iso: string | undefined) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime()) || d.getFullYear() < 2000) return "";
  return d.toLocaleString(lang, { dateStyle: "medium", timeStyle: "short" });
}

export function fmtBytes(n: number) {
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return (i === 0 ? n : n.toFixed(1)) + " " + units[i];
}

export function fmtDuration(fromIso: string | undefined) {
  if (!fromIso) return "";
  const s = Math.max(0, Math.floor((Date.now() - new Date(fromIso).getTime()) / 1000));
  const m = Math.floor(s / 60);
  const hrs = Math.floor(m / 60);
  if (hrs > 0) return t("time.hours_minutes", { h: hrs, m: m % 60 });
  if (m > 0) return t("time.minutes", { m });
  return t("time.seconds", { s });
}
