# printing

```sh
pdftops foo.pdf
lp foo.ps
```

- if "lp: Error - No default destination" => CUPS > Printers > Maintenance > Set As Server Default

# management

- CUPS
    - http://localhost:631

# debug

- set: printer status = Idle
    - if unauthorized => send POST Basic Authentication with `root` credentials

# maximize black output

- Output Mode = Color
- Media Type = Photo Paper
- Print Quality = High-Resolution Photo
