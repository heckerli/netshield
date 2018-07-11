MakeTable.py %1 %~n1.table
BuildConfig.py %~n1.table %~n1.xml
GenSeqMatchCode.py %~n1.table HTTPAnalyzerSeq.cpp
copy HTTPAnalyzerSeq.cpp ..\src /y
