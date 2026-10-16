// Tiny DOM helpers: no framework, no virtual DOM. Views build static
// skeletons once and re-render only their dynamic containers.

export type Child = Node | string | number | null | undefined | false | Child[];
type Attrs = Record<string, unknown>;

export function h(tag: string, attrs: Attrs | null = null, ...children: Child[]): HTMLElement {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k.startsWith("on") && typeof v === "function") {
        el.addEventListener(k.slice(2), v as EventListener);
      } else if (k === "class") {
        el.className = String(v);
      } else if (k === "value" && (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement)) {
        el.value = String(v);
      } else if (k === "checked" && el instanceof HTMLInputElement) {
        el.checked = Boolean(v);
      } else if (k === "html") {
        // Only ever used with trusted, locally generated markup (icons).
        el.innerHTML = String(v);
      } else if (v === true) {
        el.setAttribute(k, "");
      } else {
        el.setAttribute(k, String(v));
      }
    }
  }
  append(el, children);
  return el;
}

function append(el: Node, children: Child[]) {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) append(el, c);
    else if (c instanceof Node) el.appendChild(c);
    else el.appendChild(document.createTextNode(String(c)));
  }
}

/**
 * Replace all children of el. <details data-key="…"> elements keep the
 * open/closed state the user gave them across re-renders.
 */
export function mount(el: Element, ...children: Child[]) {
  const was = new Map<string, boolean>();
  el.querySelectorAll<HTMLDetailsElement>("details[data-key]").forEach((d) => was.set(d.dataset.key!, d.open));
  el.replaceChildren();
  append(el, children);
  el.querySelectorAll<HTMLDetailsElement>("details[data-key]").forEach((d) => {
    const open = was.get(d.dataset.key!);
    if (open !== undefined) d.open = open;
  });
}

export function $(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error("missing #" + id);
  return el;
}

export function show(el: HTMLElement, visible: boolean) {
  el.hidden = !visible;
}

let toastTimer: number | undefined;
export function toast(msg: string) {
  let el = document.getElementById("toast");
  if (!el) {
    el = h("div", { id: "toast", role: "status" });
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.classList.add("visible");
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => el!.classList.remove("visible"), 2200);
}
