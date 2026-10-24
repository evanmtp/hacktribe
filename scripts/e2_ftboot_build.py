#!/usr/bin/env python3
"""Build the Freetribe boot patch for Hacktribe 2.

Adds LOAD FREETRIBE, the last item of the DATA UTILITY menu.  Pressing
ENTER on it reads KORG/hacktribe/freetribe.bin from the SD card and starts
it, which is what scripts/execute_freetribe.py (or Freetribe's ft_load.py
--ddr) does over MIDI, so no PC or cable is needed.

    python scripts/e2_ftboot_build.py -s SYSTEM.VSB

takes the factory 2.02 SYSTEM.VSB, applies patch/hacktribe-2.patch, then
the hooks below, and writes patch/ftboot.patch (hacktribe -> hacktribe with
LOAD FREETRIBE) and hash/ftboot-*.sha.  Run it again after changing the
assembly.  e2-firmware-patch.py applies both patches.

Needs: pip install bsdiff4 keystone-engine

Addresses are those of the 2.02 application, which runs from DDR at
0xC0000000; an "image offset" is a file offset minus the 0x100 header.
Every hook site is checked against the bytes it replaces, so a patch built
for another firmware fails here rather than on the device.

The image loaded is a Freetribe DDR build (links at 0xC0000000).  It is
staged at 0xC3000000 and moved by the 132 byte stub from Freetribe's
tools/arm/tramp.S (RELOCATE), which first quiesces Korg's MMU, caches,
interrupts and the panel MCU.  The stub is the one ft_load.py sends over
USB, so the two paths start Freetribe from the same state.
"""

import argparse
import hashlib
import sys
from pathlib import Path

import bsdiff4
from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM

HEADER = 0x100
BASE = 0xC0000000

# Free (0xFF) space in the application, past Hacktribe's own additions.
CODE_AT = 0x1C0000

# Korg's FatFs and UI, as read from the 2.02 application.
F_OPEN = 0xC009DB60    # FRESULT f_open(FIL *, const char *path, mode)
F_READ = 0xC009DD74    # FRESULT f_read(FIL *, void *, btr, UINT *br)
F_CLOSE = 0xC009E3DC   # FRESULT f_close(FIL *)
SHOW_ERROR = 0xC0083DB0  # (0x1b, code): the error pop-up
SET_INDEX = 0xC008A8A8   # (indicator, index, count)
SET_TITLE = 0xC00857E4   # (label, text) first line
SET_LINE2 = 0xC0085888   # (label, text) second line
STR_PRESS_ENTER = 0xC00A5A23  # "press  [ Enter ]"

# Error pop-up codes: the text is table[code - 1], table at 0xC00E3280.
ERR_NO_CARD = 0x02     # "No Card."
ERR_FILE = 0x09        # "File Error"
ERR_NO_FILE = 0x17     # "No File"

# DATA UTILITY page: state at [page+0x20], 0..0xD are its top level items.
# 0x28 is free; LOAD FREETRIBE goes after 0xD.
NEW_STATE = 0x28

FIL_AT = 0xC3F08000    # a FIL
BR_AT = 0xC3F0F000     # the byte count f_read returns
STAGE = 0xC3000000     # tramp.S RELOCATE: FT_DDR_STAGE
STUB_AT = 0xC3F00000   # DDR_STUB_ADDRESS in ft_load.py
IMAGE_MAX = 0x00F00000  # up to the stub
MIN_IMAGE = 0x100
READ_CHUNK = 0x8000
PATH = b"SD:KORG/hacktribe/freetribe.bin\0"
TITLE = b"LOAD FREETRIBE\0"

# tools/arm/tramp.S assembled with RELOCATE; the last word is the number
# of words to copy, which is patched below for the file's size.
STUB = bytes.fromhex(
    "00000fe11f00c0e3d30080e300f021e17eff17eefdffff1a"
    "0000a0e3150f07ee9a0f07ee100f11ee0100c0e30400c0e3"
    "010ac0e3020a80e3100f01ee0000a0e3170f08ee30109fe5"
    "012ca0e3942081e5c304a0e30311a0e320209fe5000052e3"
    "0300000a043090e4043081e4012052e2fbffff1a0301a0e3"
    "10ff2fe10060e20100000000"
)

# (image offset, bytes it must hold, instruction that replaces it)
HOOKS = [
    # drawing, state > 0x27: was "b 0xc0061ea4", the end of the page's draw
    (0x61A30, "b 0xC0061EA4", "b {draw_hook}"),
    # position indicator (n of 14), state > 0xD: was "bhi 0xc0061a0c"
    (0x619A4, "bhi 0xC0061A0C", "bhi {ind_hook}"),
    # ... and its count of items: was "movne r2, #0xe"
    (0x619C4, "movne r2, #0xe", "movne r2, #0xf"),
    # encoder left and right: was "ldrb r2, [r4, #0x25]"
    (0x623F8, "ldrb r2, [r4, #0x25]", "b {dec_hook}"),
    (0x62480, "ldrb r2, [r4, #0x25]", "b {inc_hook}"),
    # ENTER: was "cmp r5, #0x1f"
    (0x62730, "cmp r5, #0x1f", "b {enter_hook}"),
    # opening the page with the sequencer running: was "bhi 0xc0062e54"
    (0x62E34, "bhi 0xC0062E54", "bhi {ctor_hook}"),
]

# Each routine is assembled on its own at its final address; {names} are
# filled in with absolute addresses, so no assembler symbols are needed.
ROUTINES = [
("ft_launch", """
@ Returns an error code; does not return when Freetribe has started.
    push    {{r4, r5, r6, r7, r8, lr}}
    ldr     r4, ={fil}
    mov     r0, r4
    ldr     r1, ={path}
    mov     r2, #1              @ FA_READ
    bl      {f_open}
    cmp     r0, #0
    bne     open_failed
    ldr     r5, [r4, #0xc]      @ file size
    cmp     r5, #{min_image}
    blo     bad_file
    ldr     r0, ={image_max}
    cmp     r5, r0
    bhi     bad_file
    ldr     r6, ={stage}
    mov     r7, r5
read_more:
    ldr     r8, ={chunk}
    cmp     r7, r8
    movlo   r8, r7
    mov     r0, r4
    mov     r1, r6
    mov     r2, r8
    ldr     r3, ={br}           @ UINT *br
    bl      {f_read}
    cmp     r0, #0
    bne     bad_file
    ldr     r3, ={br}
    ldr     r3, [r3]
    cmp     r3, r8
    bne     bad_file
    add     r6, r6, r8
    subs    r7, r7, r8
    bne     read_more
    mov     r0, r4
    bl      {f_close}
    ldr     r0, ={stub}
    ldr     r1, ={stub_at}
    mov     r2, #{stub_words}
copy_stub:
    ldr     r3, [r0], #4
    str     r3, [r1], #4
    subs    r2, r2, #1
    bne     copy_stub
    add     r3, r5, #3
    lsr     r3, r3, #2
    str     r3, [r1, #-4]       @ words for the stub to move
    mrs     r0, cpsr            @ nothing may run between here and the stub
    orr     r0, r0, #0xc0
    msr     cpsr_c, r0
clean:
    .word   0xee17ff7e          @ mrc p15, 0, pc, c7, c14, 3
    bne     clean               @ clean and invalidate the D-cache
    mov     r0, #0
    .word   0xee070f9a          @ mcr p15, 0, r0, c7, c10, 4 (drain)
    .word   0xee070f15          @ mcr p15, 0, r0, c7, c5, 0 (invalidate I)
    ldr     r0, ={stub_at}
    bx      r0

open_failed:
    cmp     r0, #4              @ FR_NO_FILE
    moveq   r0, #{err_no_file}
    beq     done
    cmp     r0, #5              @ FR_NO_PATH
    moveq   r0, #{err_no_file}
    beq     done
    cmp     r0, #3              @ FR_NOT_READY
    moveq   r0, #{err_no_card}
    beq     done
    cmp     r0, #13             @ FR_NO_FILESYSTEM
    moveq   r0, #{err_no_card}
    movne   r0, #{err_file}
    b       done
bad_file:
    mov     r0, r4
    bl      {f_close}
    mov     r0, #{err_file}
done:
    pop     {{r4, r5, r6, r7, r8, pc}}
    .ltorg
"""),
("draw_hook", """
@ r3 = state, r4 = page
    cmp     r3, #{state}
    bne     0xC0061EA4
    ldr     r0, [r4, #0x28]
    ldr     r1, ={title}
    bl      {set_title}
    ldr     r0, [r4, #0x28]
    ldr     r1, ={press}
    bl      {set_line2}
    b       0xC0061EA4
    .ltorg
"""),
("ind_hook", """
@ r3 = state, r4 = page: the new item is 15 of 15
    cmp     r3, #{state}
    bne     0xC0061A0C
    ldr     r0, [r4, #0x2c]
    mov     r1, #0xe
    mov     r2, #0xf
    bl      {set_index}
    b       0xC0061A0C
"""),
("dec_hook", """
@ r3 = state; flag [page+0x25] is set once the sequencer is stopped
    ldrb    r2, [r4, #0x25]
    cmp     r2, #0
    beq     0xC0062420          @ sequencer running: ring unchanged
    cmp     r3, #{state}
    moveq   r2, #0xd
    beq     store
    cmp     r3, #0
    moveq   r2, #{state}
    beq     store
    subs    r2, r3, #1          @ Korg's own step
    addmi   r2, r3, #0xd
    bmi     store
    cmp     r2, #0xd
    subgt   r2, r3, #0xf
store:
    str     r2, [r4, #0x20]
    b       0xC006243C
"""),
("inc_hook", """
    ldrb    r2, [r4, #0x25]
    cmp     r2, #0
    beq     0xC00624A8
    cmp     r3, #0xd
    moveq   r2, #{state}
    beq     store
    cmp     r3, #{state}
    moveq   r2, #0
    beq     store
    adds    r2, r3, #1          @ Korg's own step
    addmi   r2, r3, #0xf
    bmi     store
    cmp     r2, #0xd
    subgt   r2, r3, #0xd
store:
    str     r2, [r4, #0x20]
    b       0xC00624C4
"""),
("enter_hook", """
@ r5 = state, r4 = page
    cmp     r5, #{state}
    beq     launch
    cmp     r5, #0x1f
    b       0xC0062734
launch:
    ldrb    r0, [r4, #0x25]
    cmp     r0, #0
    beq     0xC0062AC0          @ not with the sequencer running
    bl      {ft_launch}
    mov     r1, r0
    mov     r0, #0x1b
    bl      {show_error}
    b       0xC0062AC0
"""),
("ctor_hook", """
@ page opened with the sequencer running, state > 0xD
    cmp     r3, #{state}
    moveq   r3, #2
    streq   r3, [r4, #0x20]
    b       0xC0062E54
"""),
]


def assemble(src, address):
    ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
    out, _ = ks.asm(src, address)
    return bytes(out)


def build_code(at):
    """Lay out strings, the stub and the routines from address `at`.

    Returns (bytes, {name: address})."""
    labels = {}
    blob = bytearray()

    def place(name, data):
        while len(blob) % 4:
            blob.append(0)
        labels[name] = at + len(blob)
        blob.extend(data)

    place("path", PATH)
    place("title", TITLE)
    place("stub", STUB)
    consts = dict(
        state=NEW_STATE, set_index=SET_INDEX, set_title=SET_TITLE, set_line2=SET_LINE2,
        press=STR_PRESS_ENTER, show_error=SHOW_ERROR, fil=FIL_AT,
        f_open=F_OPEN, f_read=F_READ, f_close=F_CLOSE, min_image=MIN_IMAGE,
        image_max=IMAGE_MAX, stage=STAGE, chunk=READ_CHUNK, stub_at=STUB_AT,
        br=BR_AT, stub_words=len(STUB) // 4, err_no_file=ERR_NO_FILE,
        err_no_card=ERR_NO_CARD, err_file=ERR_FILE,
    )
    for name, src in ROUTINES:
        while len(blob) % 4:
            blob.append(0)
        here = at + len(blob)
        labels[name] = here
        values = dict(consts, **labels)
        blob.extend(assemble(src.format(**values), here))
    return bytes(blob), labels


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-s", "--src", default="SYSTEM.VSB",
                    help="factory sampler 2.02 SYSTEM.VSB")
    ap.add_argument("-p", "--patch", default="patch/hacktribe-2.patch")
    ap.add_argument("-o", "--out", default="patch/ftboot.patch")
    ap.add_argument("--dump", help="also write the patched SYSTEM.VSB here")
    args = ap.parse_args()

    stock = Path(args.src).read_bytes()
    hacked = bsdiff4.patch(stock, Path(args.patch).read_bytes())
    published = Path("hash/hacked-SYSTEM.VSB.sha").read_text().split()[0]
    if hashlib.sha256(hacked).hexdigest() != published:
        sys.exit("hacktribe-2.patch does not give the published hash; "
                 "is this the 2.02 sampler SYSTEM.VSB?")
    img = bytearray(hacked)

    code, labels = build_code(BASE + CODE_AT)
    at = HEADER + CODE_AT
    if any(b != 0xFF for b in img[at:at + len(code)]):
        sys.exit("code area is not blank")
    img[at:at + len(code)] = code

    ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
    for off, old, new in HOOKS:
        site = HEADER + off
        addr = BASE + off
        have = bytes(img[site:site + 4])
        expect = bytes(ks.asm(old, addr)[0])
        if have != expect:
            sys.exit(f"hook site {addr:#x}: expected {old!r} "
                     f"({expect.hex()}), found {have.hex()}")
        img[site:site + 4] = bytes(ks.asm(new.format(**labels), addr)[0])

    final = bytes(img)
    Path(args.out).write_bytes(bsdiff4.diff(hacked, final))
    if args.dump:
        Path(args.dump).write_bytes(final)
    digest = hashlib.sha256(final).hexdigest()
    Path("hash/ftboot-hacked-SYSTEM.VSB.sha").write_text(
        f"{digest}  hacked-SYSTEM.VSB\n")
    # The synth install edits the header, as e2-firmware-patch.py -e does.
    img[0x12] = 0x00
    img[0x2E] = 0x23
    Path("hash/ftboot-modified-hacked-SYSTEM.VSB.sha").write_text(
        f"{hashlib.sha256(img).hexdigest()}  hacked-SYSTEM.VSB\n")
    print(f"{len(code)} bytes at {BASE + CODE_AT:#x}")
    for name, addr in labels.items():
        print(f"  {name:10s} {addr:#x}")
    print("sha256", digest)


if __name__ == "__main__":
    main()
