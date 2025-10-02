Educational project: a SIEM (Security Information and Event Management) in Python to learn log collection and analysis.
Goal: simulate a log stream (simple web app + honeypot) and detect a few basic cases (failed logins, many 404s, server errors). This project is experimental and not production-ready.

##Scope / current plan

Collect logs from files (access.log, honeypot_logs.log)

Simple parsing of log lines into structured objects

Basic rule-based detection (e.g., brute-force on 401, accumulation of 404, 5xx)

Output alerts to the console (log)

##How to test quickly
  /
##Example expected alert

[ALERT] BRUTE_FORCE - 198.51.100.5 - 6 failed logins


##Roadmap (progressive)

V0: log generator + simple analyzer (targeted now)

V1: add a more robust parser + local storage

V2: optional — small Flask app to produce real logs

V3: integrate honeypot and better correlation rules

##Security notes

Educational use only.

Do not run against systems or networks you do not control or have authorization to test.

The honeypot must log only metadata (IP, port, timestamp).
