cd ..\..\gnuwin32\bin
flex.exe -o..\..\ultrapac\src\pac_scan.cc ..\..\ultrapac\src\pac_scan.ll
bison.exe -d -v -t -o..\..\ultrapac\src\pac_parse.cc ..\..\ultrapac\src\pac_parse.yy
del ..\..\ultrapac\src\pac_parse.h /q
rename ..\..\ultrapac\src\pac_parse.hh pac_parse.h
cd ..\..\ultrapac\proj

vcbuild /rebuild UltraPac.vcproj Release

cd ..\pac\http
call Make.bat
cd ..\..\proj
