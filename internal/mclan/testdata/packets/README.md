# LAN announcement fixtures

Each `.bin` file is one UDP payload as sent to `224.0.2.60:4445`;
`expected.json` lists how it must parse.

The vanilla files reproduce, byte for byte, the payload built by Minecraft's
`LanServerPinger` (`"[MOTD]" + motd + "[/MOTD][AD]" + port + "[/AD]"`,
UTF-8), including a Chinese world name and `§` formatting codes. They were
not captured from a live game in CI. To add a real capture, run on a machine
with Minecraft open to LAN:

    lanyard-core capture-lan internal/mclan/testdata/packets

and add the new file to `expected.json`.

`missing_motd.bin` has an AD tag but no `[/MOTD]` tag. Minecraft's
`parseAddress` looks for the AD tag only after `[/MOTD]`, so it ignores the
packet, and so does LANyard.
