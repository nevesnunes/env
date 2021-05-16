# TODO write a description for this script
# @author
# @category _NEW_
# @keybinding
# @menupath
# @toolbar

import re


def uchar(char):
    if char < 0:
        return 256 + char

    return char


def xvalue(address):
    return int(str(address), 16)


def list_dead_code():
    func = getFirstFunction()
    while func is not None:
        references = list(map(lambda x: str(x), getReferencesTo(func.getEntryPoint())))
        if len(references) < 1:
            print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
        func = getFunctionAfter(func)


def undefined_blocks():
    blocks = currentProgram.getMemory().getBlocks()
    text_start = None
    text_end = None
    for block in blocks:
        if ".text" not in block.getName():
            continue

        text_start = block.getStart().getPhysicalAddress()
        text_end = block.getEnd().getPhysicalAddress()
        break

    bodies = []
    func = getFirstFunction()
    while func is not None:
        body = list(func.getBody().getAddressRanges())
        for subbody in body:
            bodies.append(
                [
                    subbody.getMinAddress().getPhysicalAddress(),
                    subbody.getMaxAddress().getPhysicalAddress(),
                ]
            )

        func = getFunctionAfter(func)

    bodies.sort(key=lambda x: xvalue(x[0]))

    extra_re = re.compile(b"^((\x00*)|(\xcc*))$", re.MULTILINE)
    target_block = text_start
    for body in bodies:
        if target_block > text_end:
            break

        # Skip over small blocks
        offset_diff = abs(xvalue(target_block) - xvalue(body[0]))
        if offset_diff > 6:
            # Skip over junk blocks
            # FIXME: Assuming instruction at target_block is `RET` (1 byte)
            target_bytes = bytearray(
                [uchar(c) for c in getBytes(target_block, offset_diff)[1:]]
            )
            if len(extra_re.findall(target_bytes)) == 0:
                print(
                    "Undefined block at: {}, size: {}".format(
                        hex(xvalue(target_block)), offset_diff
                    )
                )

        target_block = body[1]


undefined_blocks()
