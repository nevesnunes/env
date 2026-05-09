" Vim syntax file
" Language:		BlitzMax NG
" Maintainer:	@Hezkore
" Last Change:	2021

" Quit when a syntax file was already loaded
if exists("b:current_syntax")
	finish
endif

" Setup
let s:cpo_save = &cpo
set cpo&vim

syn case ignore

" Syntax

" Keyword			any other keyword
syn keyword bmxKeyword New AppTitle
syn match bmxKeyword '\<\(Implement\|Extends\|End\|Local\|Global\|Field\|Strict\|SuperStrict\|Public\|Private\|Return\|Module\|ModuleInfo\)\>'
syn match bmxKeyword '^\s*#'
" should we separate these?
" I feel like that's overkill but this will have matching errors
"syn match bmxKeywordError '\<\(Function\|Method\|Type\|Struct\|Enum\|Extern\)\>'
"syn match bmxKeywordError '\<End\s*\(Function\|Method\|Type\|Struct\|Enum\|Extern\)\>'
"syn region bmxKeywordContainer transparent start='^\s*\(Function\|Method\|Type\|Struct\|Enum\|Extern\)\>' end='^\s*End\s*\(Function\|Method\|Type\|Struct\|Enum\|Extern\)\s*$' contains=ALLBUT,bmxKeywordError
syn match bmxKeyword '^\s*\(Function\|Method\|Type\|Struct\|Enum\|Extern\)\>'
syn match bmxKeyword '^\s*End\s*\(Function\|Method\|Type\|Struct\|Enum\|Extern\)\s*$'

" Constant			any constant
syn keyword bmxConstant Null Super Self
syn match bmxConstant '^\s*\<const\>'

" String			a string constant: "this is a string"
syn region bmxString start='"' end='"' contains=bmxUnderlined

" Number			a number constant: 234, 0xff
syn match bmxNumber '\<\(\.\)\@<!\d\+\(\.\)\@!\>'

" Boolean			a boolean constant: TRUE, false
syn match bmxBoolean '\<\(true\|false\)\>'

" Float				a floating point constant: 2.3e10
syn match bmxFloat '\<\d\+\.\d*\>'
" FIX can't figure out why the period isn't matched
" "\.\d\+\>" doesn't seem to work either
syn match bmxFloat '\(\.\)\@<=\d\+\>'

" Identifier		any variable name

" Function			function name (also: methods for classes)
syn match bmxFunction "\(New\s\+\w*\)\@<!\w*\s*\(\(\:\s*\w\+\|%\|#\|!\|\$\)\s*(\|(\)\@="

" Statement			any statement

" Conditional		if, then, else, endif, switch, etc.
syn match bmxConditional '\<\(If\s\+\|Else\)'
syn match bmxConditional '\<\(Else\s*If\|End\s*Select\|Select\|End\s*If\|Then\)\>'
syn keyword bmxConditional And Not Or

" Repeat			for, do, while, etc.
syn match bmxRepeat '\<\(While\|WEnd\|For\|Next\|Exit\|To\|Until\|Step\|EachIn\|Continue\|Repeat\|Until\|Forever\)\>'

" Label				case, default, etc.
syn match bmxLabel '^\s*\(Case\s\+\|Default\s*\>\)'

" Operator			"sizeof", "+", "*", etc.
syn match bmxOperator "\(\.\|,\|\:\|=\|+\|-\|*\|/\|\~\|\^\|<\|>\)"

" Exception			try, catch, throw
syn match bmxException '\<\(Try\|Catch\|End\s*Try\)\>'

" PreProc			generic Preprocessor
syn match bmxPreProc '^\s*?\.*'

" Include			preprocessor #include
syn match bmxInclude '^\s*\<\(Framework\|Include\|Import\|Incbin\)\>'

" Define			preprocessor #define
" Macro				same as Define

" PreCondit			preprocessor #if, #else, #endif, etc.
syn match bmxPreCondit '^\s*?\(Not\)'

" Type				int, long, char, etc.
syn match bmxType "\w*\(\:\s*\)\@<=\(\w\+\)"
syn match bmxType "\(^\s*Type\s*\)\@<=\w\+"
syn match bmxType "\(\:\)\@<!\(\w\+\)\@<=\s*\(%\|#\|!\|\$\)"
syn match bmxType "\(New\|Implements\|Extends\)\@<=\s\+\w*"

" StorageClass		static, register, volatile, etc.

" Structure			struct, union, enum, etc.

" Typedef			A typedef

" Special			any special symbol
" SpecialChar		special character in a constant
" Tag				you can use CTRL-] on this

" Delimiter			character that needs attention
" Comment
syn match bmxComment "'.*" contains=bmxTodo,bmxUnderlined
syn region bmxComment start="^\s*Rem\(\s\+\w*\|$\)" end="^\s*End\s*Rem\>" contains=bmxTodo,bmxUnderlined

" SpecialComment	special things inside a comment
" what skin even highlights 'SpecialComment'?!
" let's just use Todo instead...
syn match bmxTodo '\(\(^\|\'\)\s*\)\@<=\w\+:'me=e-1 contained

" Debug				debugging statements
syn keyword bmxDebug DebugStop DebugLog RuntimeError Assert

" Underlined		text that stands out, HTML links
" Ignore			left blank, hidden  |hl-Ignore|
" Error				any erroneous construct

" Todo				anything that needs extra attention; mostly the keywords TODO FIXME and XXX
syn match bmxTodo '\<\(TODO\|BUG\|FIXME\|XXX\)\>' contained

" Character			a character constant: 'c', '\n'
syn match bmxCharacter '\~\(q\|t\|n\|r\)'

" Default highlighting
hi def link bmxConstant			Constant
hi def link bmxString			String
hi def link bmxCharacter		Character
hi def link bmxNumber			Number
hi def link bmxBoolean			Boolean
hi def link bmxFloat			Float
hi def link bmxIdentifier		Identifier
hi def link bmxFunction			Function
hi def link bmxStatement		Statement
hi def link bmxConditional		Conditional
hi def link bmxRepeat			Repeat
hi def link bmxLabel			Label
hi def link bmxOperator			Operator
hi def link bmxKeyword			Keyword
hi def link bmxException		Exception
hi def link bmxPreProc			PreProc
hi def link bmxInclude			Include
hi def link bmxDefine			Define
hi def link bmxMacro			Macro
hi def link bmxPreCondit		PreCondit
hi def link bmxType				Type
hi def link bmxStorageClass		StorageClass
hi def link bmxStructure		Structure
hi def link bmxTypedef			Typedef
hi def link bmxSpecial			Special
hi def link bmxSpecialChar		SpecialChar
hi def link bmxTag				Tag
hi def link bmxDelimiter		Delimiter
hi def link bmxComment			Comment
hi def link bmxSpecialComment	SpecialComment
hi def link bmxDebug			Debug
hi def link bmxUnderlined		Underlined
hi def link bmxIgnore			Ignore
hi def link bmxError			Error
hi def link bmxTodo				Todo

hi def link bmxKeywordError		Error

let b:current_syntax = "bmx"

let &cpo = s:cpo_save
unlet s:cpo_save

" vim: ts=8
