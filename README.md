# NetShield, A Research Prototype of Vunerability Signature Based Network Intrusion Detection System

## Introduction
This is a research prototype level implementation based on the design proposed
in the ACM SIGCOMM 2010 research paper "NetShield: Matching with a Large
Vulnerability Signature Ruleset for High Performance Network Defense".

At high level, we would like to demonstrate with layer-7 application protocol
level parsing, and with defining vulnerability-signatures based on the parsed protocol
fields, that vulnerability-signatures dramatically improve the expressiveness
and more precisely describe the condition might trigger vulnerabilities than
existing string or regular-expression (regexes) based signatures.

We also demonstrated through UltraPAC, we can create very-fast layer-7 application
protocol level parsers through the PAC parser specification language inherit
from [BinPAC](https://www.bro.org/sphinx/components/binpac/README.html).
Furthermore, we design and implemented candidate selection algorithms which
can dramatically speed-up the multi-field vulnerability-signature matching
speed.

Currently, the implementation remains in the research prototype stage. In other
words, it is good to demonstrate the concept, but not engineeringly mature enough
as we hope it can be yet. Therefore, use it at your own risk.

## Build
Building Requirement: Visual Studio 2008 with SP1 and Python 2.5 or 2.6 installed.
Python is used to compile the ruleset to the XML format matrix to be loaded
by the main program.

Here are the list of steps for building the project
1. Enter ..\proj and modify "VCBUILD_PATH" in Make.bat to identify the path of "vcbuild.exe" of VS 2008.

2. run Make.bat, then the generated executables will be in ..\bin\Release.

3. The solution can also be opened and compiled by proj\NetShield.sln.

4. The test sample is in test\.
