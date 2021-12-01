ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp UnhookIAT.cpp /link /OUT:UnhookIAT.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
del *.obj
