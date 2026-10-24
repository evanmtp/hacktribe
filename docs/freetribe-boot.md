# Load Freetribe from the Electribe

`DATA UTILITY` has a last item, **LOAD FREETRIBE**. It reads
`KORG/hacktribe/freetribe.bin` from the SD card and starts it, as
`scripts/execute_freetribe.py` does over MIDI, so no PC or cable is needed.
Nothing is flashed by the menu item, and a power cycle returns to Hacktribe.

## Use

1. Build a Freetribe **DDR** image (links at `0xC0000000`, for example
   `tools/device_build.sh --ddr` in freetribe-em, which writes
   `temp/multi-app-ddr.bin`).
2. Copy it to the SD card as `KORG/hacktribe/freetribe.bin`.
3. Stop the sequencer, open `DATA UTILITY` as you would for export or import,
   turn the encoder to the last item and press `ENTER`.

With the sequencer running the item is not offered, as for Korg's own
export and import items. Errors show as Korg's pop-ups: `No Card.`,
`No File` (file or folder missing), `File Error` (unreadable, under 256
bytes or over 15 MB).

## Install

```sh
python scripts/e2-firmware-patch.py        # sampler
python scripts/e2-firmware-patch.py -e     # synth hardware
```

`--no-ftboot` gives plain Hacktribe. `patch/ftboot.patch` is applied on top of
`patch/hacktribe-2.patch`; `scripts/e2_ftboot_build.py` regenerates it, with
its hashes, from the factory 2.02 `SYSTEM.VSB` (needs `bsdiff4` and
`keystone-engine`).

## How it works

The menu is a state machine (state at page+0x20, 0..0xD the items). The patch
adds state 0x28 with hooks in the draw routine, both encoder directions, the
ENTER handler and the page constructor, all in
`scripts/e2_ftboot_build.py`. ENTER calls Korg's own FatFs (`f_open`,
`f_read`, `f_close`), reads the file to `0xC3000000`, copies the relocating
stub from Freetribe's `tools/arm/tramp.S` to `0xC3F00000`, cleans the caches
and jumps to it. The stub quiesces Korg's MMU, caches, interrupts and panel
MCU, moves the image to `0xC0000000` and starts it: the state the
`ft_load.py --ddr` USB path produces.

The code sits in blank space at `0xC01C0000`.

## Checked and not checked

Checked on an Electribe 2 sampler: the item appears as 15 of 15, ENTER loads a
322 KB Freetribe DDR image from the SD card and Freetribe runs.

Also checked by emulating the real 2.02 code (Unicorn) with the patch
applied: the item ring in both directions with the sequencer stopped and
running (the other 14 items behave as before), the item's text and
indicator, ENTER with file sizes from 10 bytes to 70 KB, each error path,
the staged bytes against the file, and the stub copy and its word count.

Not checked: synth hardware (`-e`), and the error pop-ups other than `No File`
on a device.
