// $Id: .indent.pro 193 2008-07-17 04:34:28Z tsuruda $

// Blank lines
-bap -nsob

// Comments
-c0

// Statements
-npcs -br -ce -cdw -cs -saf -sai -saw

// Declarations
-psl -brs

// Indentation
-i4 -nut -ts4 -lp -lps
// -ppi3

// Breaking long lines
-l100 -bbo

// POSIX types
-T bool
-T socklen_t -T FILE
-T size_t -T ssize_t
-T pthread_t -T pthread_mutex_t -T pthread_cond_t

// libmilter
-T SMFICTX -T sfsistat -T _SOCK_ADDR

// libsidf
-T SidfPolicy -T SidfRecord -T SidfRecordScope -T SidfScore
-T SidfRequest -T SidfMacro -T SidfTerm -T SidfTermAttribute -T SidfRawRecord
-T DnsAResponse -T DnsAaaaResponse -T DnsMxResponse
-T DnsTxtResponse -T DnsSpfResponse -T DnsPtrResponse
-T XBuffer -T PtrArray -T StrArray -T StrPairArray -T IntArray -T FoldString
-T DnsResolver -T InetMailbox -T KeywordMap -T MailHeaders
-T AuthResult

// enma
-T EnmaConfig -T ConfigEntry -T SyslogFacilityTbl -T SyslogPriorityTbl
-T EnmaMfiCtx
