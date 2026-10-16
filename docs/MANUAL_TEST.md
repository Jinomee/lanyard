# Manual real-world test

CI proves the logic in emulated networks. Only real routers, ISPs and the
Great Firewall can prove the product. Run this before every release that
changes networking, with a friend on a **different network**. Ideally do it a
second time with one person in **mainland China** and one outside.

Use the CI build artifact (`LANyard-windows-<run>`) or a release candidate.
Record results in the release PR or issue (copy the table at the end).

## Setup (both people)

- [ ] Note your setup: ISP, country/city, router model, Wi-Fi or Ethernet, and whether you are on a phone hotspot.
- [ ] Install with the **installer** on one PC and use the **portable exe** on the other (this covers both firewall paths).
- [ ] Both: open **Diagnostics → Test my network** and write down NAT type, IPv6, port mapping, CGNAT and how many STUN servers answered. In China, check that at least the Xiaomi/Bilibili/Douyu/CDNBye servers answer.
- [ ] Both: Minecraft Java Edition, same version (one recent 1.21.x run and one 1.20.1 run if possible).

## A. Host an "Open to LAN" world

- [ ] Host: open a world → Esc → Open to LAN → Start LAN World.
- [ ] Host: LANyard → Host → Start hosting. The world name appears within ~2 s ("Sharing your world …").
- [ ] Portable exe only: Windows shows the firewall prompt and LANyard shows its guide. Tick both boxes → Allow. (Installer: no prompt should appear.)
- [ ] Host: copy the code and send it through **WeChat** or **QQ**. Check the code arrives intact (no line breaks or auto-links). Also try sending the `lanyard://` link.
- [ ] Guest: copy the code from the chat app and focus LANyard. The **"Join this world?"** banner appears. Click Join.
- [ ] Guest: within ~6 s, either **Connected**, or **One more step** with a reply code.
    - [ ] If a reply code appears: send it to the host. The host's app offers it from the clipboard ("A reply code from a friend…"), or the host pastes it under Host. Connection should follow within ~10 s.
- [ ] Guest: Minecraft → Multiplayer. The world appears in the LAN list as "<world> (via LANyard)". Join it.
- [ ] Guest: also try Direct Connection with the `127.0.0.1:port` address shown.
- [ ] Play for 10+ minutes: walk far (chunk loading), open chests, chat. Note lag or disconnects.
- [ ] Host: Esc → close the LAN world and reopen it (Minecraft picks a **new port**). LANyard picks up the new world. The guest leaves and rejoins from the LAN list without a new code.
- [ ] Host: **Disconnect** the guest. Guest sees "Your friend disconnected you". Guest clicks Reconnect. It works.
- [ ] Host: **New code**. Guest tries the old code and sees "no longer valid". The new code works.
- [ ] Host: Settings → enable "Ask me before each friend joins". Guest joins and the host sees Allow/Deny. Test both buttons.
- [ ] Online mode: guest with a different Microsoft account joins the world. (Optional) an offline/cracked launcher is rejected by the host's game exactly as on a LAN. LANyard must not change this.

## B. Dedicated server on the host's PC

- [ ] Host: run a vanilla server (`server.jar`) on port 25565 with `online-mode=true`.
- [ ] Host: Host → "A Minecraft server on this computer", port 25565 → Start hosting. It shows "Minecraft server found on port 25565".
- [ ] Guest joins and plays. Stopping the server makes the host show "Nothing is listening…".

## C. Roles swapped

- [ ] Repeat A quickly with the guest hosting. Note which direction needed a reply code.

## D. Failure paths and guidance

- [ ] Join with a **truncated** code (delete the last few characters). You get "incomplete or has a typo".
- [ ] Paste a **reply code** under Join. You get "That's a reply code…".
- [ ] One side on a **phone hotspot** (often symmetric NAT / CGNAT), the other at home. Note the result and whether the advice shown makes sense.
- [ ] If a connection fails: the guidance names a concrete next step (let the other person host, enable UPnP, hotspot, IPv6). Paste the advice text into the report.
- [ ] Diagnostics → **Export logs** on both sides and attach the zips to the report.

## E. Housekeeping

- [ ] Close the LANyard window while a friend is connected. A confirmation appears. After quitting, the friend is disconnected and `LANyard.exe` disappears from Task Manager within ~1 minute (the core's idle exit).
- [ ] Settings → language switch EN ↔ 简体中文: every screen is translated, with no `key.like.this` strings.
- [ ] Installer: Start-menu entry exists. `lanyard://join/<code>` from a browser address bar opens LANyard and starts joining. Uninstall removes the firewall rule (`wf.msc`).
- [ ] Update check (once the signing key and a release exist): "LANyard x.y.z is available" appears, and Download opens the browser without installing anything.

## Report template

| Date | Host network (ISP, country, NAT type, IPv6, UPnP) | Guest network | Method that won (from Join → Connection attempts) | Reply code needed? | Result / notes |
|---|---|---|---|---|---|
| | | | | | |
