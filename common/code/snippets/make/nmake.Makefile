# Microsoft Developer Studio Generated NMAKE File, Based on $(BIN).dsp

# References:
# - https://docs.microsoft.com/en-us/cpp/build/reference/sample-makefile?view=msvc-160
# - http://tmake.sourceforge.net/m-win32-msvc.html
# - [GNU Make - Using Implicit Rules - Old-Fashioned Suffix Rules](http://web.mit.edu/gnu/doc/html/make_10.html#SEC99)

CPP=cl.exe

OUTDIR=.\Bin
INTDIR=.\Debug

BIN = _

ALL : "$(OUTDIR)\$(BIN).exe"

CLEAN :
	-@erase "$(INTDIR)\$(BIN).obj"
	-@erase "$(INTDIR)\$(BIN).pch"
	-@erase "$(INTDIR)\StdAfx.obj"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\$(BIN).exe"
	-@erase "$(OUTDIR)\$(BIN).ilk"
	-@erase "$(OUTDIR)\$(BIN).pdb"

"$(OUTDIR)" :
	mkdir "$(OUTDIR)" > nul 2>&1 || (exit 0)

CPP_PROJ=/nologo /MLd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fp"$(INTDIR)\$(BIN).pch" /Yu"stdafx.h" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ  /c 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\$(BIN).bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib  kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:yes /pdb:"$(OUTDIR)\$(BIN).pdb" /debug /machine:I386 /out:"$(OUTDIR)\$(BIN).exe" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\StdAfx.obj" \
	"$(INTDIR)\$(BIN).obj"

"$(OUTDIR)\$(BIN).exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<


SOURCE=.\$(BIN).cpp

"$(INTDIR)\$(BIN).obj" : $(SOURCE) "$(INTDIR)" "$(INTDIR)\$(BIN).pch"


SOURCE=.\StdAfx.cpp

CPP_SWITCHES=/nologo /MLd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fp"$(INTDIR)\$(BIN).pch" /Yc"stdafx.h" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ  /c 

"$(INTDIR)\StdAfx.obj"	"$(INTDIR)\$(BIN).pch" : $(SOURCE) "$(INTDIR)"
	$(CPP) @<<
  $(CPP_SWITCHES) $(SOURCE)
<<
