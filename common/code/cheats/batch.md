# Debug

```
s/^\(::\|REM\) \+\(@ECHO OFF\)/\2/
```

```bat
:: Check referenced variables:
SET fooVariable
:: Output:
:: fooVariable=fooValue

SETLOCAL ENABLEDELAYEDEXPANSION
FOR %%A IN (1 2 3) DO (
	SET fooVariable
)

:: Split commands with pipes and check each input to each pipe:
TYPE %foo%
ECHO ====
TYPE %foo% | FIND "bar"

:: Count subroutine calls:
SET Counter=0
SET /A Counter += 1
SET
```

- https://www.robvanderwoude.com/battech_debugging.php
- https://www.robvanderwoude.com/battech_bestpractices.php
- https://www.robvanderwoude.com/battech_batcodecheck.php


