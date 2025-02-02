# AWS WAF CloudWatch Log Insight QL

--------------------------

## 1. Top100 IPs Count with Country origin:

```ql
fields httpRequest.clientIp, httpRequest.country
| stats count(*) as requestCount by httpRequest.clientIp, httpRequest.country
| sort requestCount desc
| limit 100
```

## 2. Top100 Countries Count:

```ql
fields httpRequest.country
| stats count(*) as requestCount by httpRequest.country
| sort requestCount desc
| limit 100
```

## 3. Top1000 User-Agent with httpRequest.uri Count:

```ql
fields @timestamp, @message, httpRequest.clientIp, httpRequest.headers.4.name as userAgent
| stats count() as requestCount by httpRequest.clientIp, userAgent, httpRequest.country, httpRequest.uri
| sort requestCount desc
| limit 1000
```

## 4. Top100 User-Agent, host with httpRequest.uri, Countries and client IPs for specific rule ID:

```ql
fields @timestamp, @message, httpRequest.clientIp, httpRequest.headers.4.name as userAgent
| filter @message like /"ruleGroupId":"AWS#AWSManagedRulesBotControlRuleSet"/
| parse @message /"name":"Host","value":"(?<host>[^"]+)"/
| stats count() as requestCount by httpRequest.clientIp, userAgent, host, httpRequest  
  country, httpRequest.uri
| sort requestCount desc
| limit 100
```

## 5. Top100 Cross-Site Scripting (XSS) or SQL Injection

```ql
fields @timestamp
| parse @message ',"terminatingRuleMatchDetails":[*],' as terminatingRuleMatchData
| filter (terminatingRuleMatchData like /XSS/ or terminatingRuleMatchData like /SQL/)
| display @timestamp, httpRequest.clientIp, httpRequest.country, terminatingRuleMatchData, httpRequest.requestId
| limit 100
```

## 6. Filter requests blocked by rate-based rules

```ql
fields @timestamp, httpRequest.clientIp as ClientIP, httpRequest.uri as URI, terminatingRuleId as rule, httpRequest.country as Country
| filter action = "ALLOW"
| filter terminatingRuleType = "RATE_BASED"
| sort @timestamp desc
```

## 7. Specific ClientIp with URI, action

```ql
fields @timestamp, httpRequest.clientIp as clientIp, httpRequest.country as country, httpRequest.uri as ReqUrl
| filter action = 'BLOCK'
| filter clientIp = '117.197.104.162'
| sort @timestamp desc
| display clientIp, country, ReqUrl, action
| limit 10000
```

## 8. AFPL WAF Report for BLOCK V1.0

```ql
fields @timestamp, httpRequest.clientIp as clientIp, httpRequest.country as country, httpRequest.uri as ReqUrl, 
| sort @timestamp desc
| display @timestamp, clientIp, country, action, ReqUrl, labels.0.name, labels.1.name, labels.2.name
| limit 100
```

## 9. AFPL WAF Report for BLOCK V2.0

```ql
fields @timestamp, httpRequest.clientIp as clientIp, httpRequest.country as country, httpRequest.uri as ReqUrl
| sort @timestamp desc
| filter action = 'BLOCK'
| parse @message /\{"name":"(U|u)ser-(A|a)gent","value":"(?<userAgent>.*?)"\}/
| parse @message '{"name":"Host","value":"*"}' as host
| display @timestamp, clientIp, country, action, ReqUrl, , terminatingRuleId, userAgent, host, labels.0.name, labels.1.name, labels.2.name
| limit 10000
```

## 10. AFPL WAF Report for BLOCK V3.0

```ql
fields @timestamp as DateTime, httpRequest.clientIp as SourceIp, httpRequest.country as Country, action as Action, httpRequest.uri as RequestUrl, terminatingRuleId as TerminatingRuleId
| sort @timestamp desc
| filter action = 'BLOCK'
| parse @message /\{"name":"(U|u)ser-(A|a)gent","value":"(?<userAgent>.*?)"\}/ as UserAgent
| parse @message '{"name":"Host","value":"*"}' as Host
| display DateTime, SourceIp, Country, Action, RequestUrl, TerminatingRuleId, UserAgent, Host, labels.0.name, labels.1.name, labels.2.name
| limit 10000
```