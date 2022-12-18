rule PExored {
    strings:
        $ = "This program" xor(0x01-0xFF)
    condition:
        all of them
}
