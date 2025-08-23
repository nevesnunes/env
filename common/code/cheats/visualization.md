# case studies

- https://blog.valerieaurora.org/2008/02/17/howto-debug-silent-data-corruption/
    - Summarize patterns as chars, run while loop with `less`, hit `q` quickly to cycle
        > Take only the first part of a disk and print out an ASCII character for each 512 byte block representing the content of the block (all zeroes, all ones, or mixed)
        > Hitting ‘q’ quickly to cycle through the output for different disks let me visually detect common patterns in the corruption; the uncorrupted disk allowed me to distinguish signal from noise
    - Alternatives:
        ```bash
        # Summarize patterns against base file
        ls -1 | xargs -i hexdiff.py 1 {}
        # `C-j` for cycling buffers, `:M` to highlight patterns that will blink on cycling
        # vs. `less`: refresh rate without lag
        vim -U NONE *

        # to byte ranges
        head -c1024 /dev/urandom | python -c 'import io, sys; [sys.stdout.buffer.write(" ".encode() if ord(x) == 0 else "1".encode() if ord(x) < 32 else "2".encode() if ord(x) < 128 else "3".encode()) for x in io.TextIOWrapper(sys.stdin.buffer, encoding="latin-1").read()]' >1024asc
        # viz
        uxterm -rv -fa 'M+ 1m' -fs 2 -e vim -c 'set nonumber nolinebreak nobreakindent showbreak=' -c 'M 1' -c 'M 2' -c 'M 3' 1024asc
        ```
- [GitHub \- mist64/visualize\_1541: A tool that creates visualizations of the data layout on Commodore 1541 disk images](https://github.com/mist64/visualize_1541)
- https://www.robertxiao.ca/hacking/dsctf-2019-cpu-adventure-unknown-cpu-reversing/
    > resizing a text window until the line-wrap length matches the file alignment
    - Alternatives:
        ```bash
        # to bits
        head -c$((1024 * 1024)) /dev/urandom >1024raw
        <1024raw python -c 'import io, sys; [sys.stdout.buffer.write(" ".encode() if x == "0" else "1".encode()) for y in io.TextIOWrapper(sys.stdin.buffer, encoding="latin-1").read() for x in bin(ord(y))[2:].zfill(8)]' >1024bits
        # viz
        uxterm -rv -fa 'M+ 1m' -fs 2 -e vim -c 'set nonumber nolinebreak nobreakindent showbreak=' -c 'M 1' -c 'M 2' -c 'M 3' <(fold -b512 1024bits)
        ```
- [GitHub \- brandtbucher/specialist: Visualize CPython&\#39;s specializing, adaptive interpreter\. :fire:](https://github.com/brandtbucher/specialist)
- https://en.wikipedia.org/wiki/User:Cmglee
