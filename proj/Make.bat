set VCBUILD_PATH="C:\Program Files\Microsoft Visual Studio 9.0\VC\vcpackages"

path %PATH%;%VCBUILD_PATH%

rem Compile rules
cd ..\rule
call Compile.bat vulsig-http-sample-0.1.rules
cd ..\proj

rem Build UltraPac
cd ..\tool\ultrapac\proj
call Make.bat
cd ..\..\..\proj

rem Build TCPReassembler
cd ..\tool\tcpreassembler\proj
call Make.bat
cd ..\..\..\proj

rem Build NetShield
vcbuild /rebuild NetShield.vcproj Release
