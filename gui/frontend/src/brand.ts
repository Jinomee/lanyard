import { Brand } from "../wailsjs/go/main/App";

export interface BrandInfo {
  name: string;
  nameZh: string;
  id: string;
  version: string;
  repo: string;
  os: string;
}

let info: BrandInfo = { name: "", nameZh: "", id: "", version: "", repo: "", os: "" };

export async function loadBrand() {
  info = (await Brand()) as BrandInfo;
}

export function brandInfo() {
  return info;
}
