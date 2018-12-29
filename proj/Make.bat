set VCBUILD_PATH="D:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcpackages"

path %PATH%;%VCBUILD_PATH%

rem Compile rules
cd ..\rule\HTTP
call Compile.bat vulsig-http-sample-0.1.rules
cd ..\..\proj

cd ..\rule\WINRPC
call Compile.bat vulsig-winrpc-sample-0.1.rules
cd ..\..\proj

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
