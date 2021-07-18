" References:
" - https://aluigi.altervista.org/papers/quickbms.txt
" - https://aluigi.altervista.org/bms/userDefineLang.xml

if exists("b:current_syntax")
    finish
endif

syntax sync minlines=200

syn case ignore
syn match bmsComment "^\s*#.*$"
syn keyword bmsConditional if else elif endif do while for next
syn keyword bmsStatement QuickBMSver Clog FindLoc Get GetDString GoTo IDString Log Math Open SavePos Set String CleanExit Exit GetCT ComType ReverseLong ReverseShort ReverseLongLong Endian FileXOR FileRot FileCrypt Strlen GetVarChr PutVarChr Debug Padding Append Encryption Print GetArray PutArray SortArray CallFunction ScanDir CallDLL Put PutDString PutCT GetBits PutBits Include Prev Xmath NameCRC Codepage Slog Label Reimport
syn keyword bmsType alloc asize asm basename binary bms_folder byte clsid compressed current_folder double exe_folder extension file_folder filename filepath float fullbasename fullname i16 i32 i64 i8 input_folder int ipv4 ipv6 line long longdouble longlong output_folder prompt regex short string tcc threebyte time time64 to_unicode u16 u32 u64 u8 uint unicode unicode32 variable variable2 variable3 variable4 variable5 variable6 variable7 variant
syn match bmsNumber "\<\(0[bB][0-1]\+\|0[0-7]*\|0[xX]\x\+\|\d\(\d\|_\d\)*\)[lL]\=\>"
syn match bmsNumber "\(\<\d\(\d\|_\d\)*\.\(\d\(\d\|_\d\)*\)\=\|\.\d\(\d\|_\d\)*\)\([eE][-+]\=\d\(\d\|_\d\)*\)\=[fFdD]\="
syn match bmsNumber "\<\d\(\d\|_\d\)*[eE][-+]\=\d\(\d\|_\d\)*[fFdD]\=\>"
syn match bmsNumber "\<\d\(\d\|_\d\)*\([eE][-+]\=\d\(\d\|_\d\)*\)\=[fFdD]\>"
syn region bmsString start=+'+ end=+'+ oneline
syn region bmsString start=+"+ end=+"+ oneline

hi def link bmsComment Comment
hi def link bmsConditional Conditional
hi def link bmsNumber Number
hi def link bmsStatement Statement
hi def link bmsString String
hi def link bmsType Type

let b:current_syntax = "bms"
