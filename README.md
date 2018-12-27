# NetShield, A Research Prototype of Vunerability Signature Based Network Intrusion Detection System 

## Introduction
NetShield Vulnerability Signature Matching Engine

## Build
Building Requirement: Visual Studio 2008 with SP1 and Python 2.5 or 2.6 installed. Python is used to compile the ruleset to the XML format matrix to be loaded by the main program 

### Build the main program 
1. Build Enter \proj and modify "VCBUILD_PATH" in Make.bat to identify the path of "vcbuild.exe" of VS 2008.

2. run Make.bat, then the generated executables will be in ..\bin\Release.

3. The solution can also be opened and compiled by proj\NetShield.sln.

4. The test sample is in test\.
