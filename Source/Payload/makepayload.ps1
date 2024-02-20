&"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64\ml64.exe" `
	payload.asm /c /Zi

&"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64\link.exe" `
	payload.obj /debug /subsystem:console /out:payload.exe `
	"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib" `
	"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64\ucrt.lib" `
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133\lib\x64\msvcrt.lib" `
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133\lib\x64\legacy_stdio_definitions.lib" `
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133\lib\x64\legacy_stdio_wide_specifiers.lib" `
	"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.29.30133\lib\x64\vcruntime.lib"