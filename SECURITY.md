---
OS/FT Analyzer (OSTE.py) — AI Prompts & Instructions Reference

This page documents exactly what is sent to the AI (LLM) by the script, and what instructions it's given at each step, so the assessment logic is transparent and reviewable.

1. AI Provider & Models

All AI calls go through Groq (https://api.groq.com/openai/v1/chat/completions), using a fixed fallback chain of three models. The script tries them in order and moves to the next one only if a model is rate-limited, errors out, or is unavailable:

llama-3.3-70b-versatile (tried first)
llama-3.1-70b-versatile (fallback)
llama-3.1-8b-instant (final fallback)

There is no OpenRouter or Gemini fallback in this version — Groq only.

The script makes two AI calls per analysis run:

Call  — Security assessment (the real risk verdict)
2. AI Call 2 — Security Assessment ("LLM-2")

This is the real assessment call. It has two parts: a system prompt (fixed instructions defining the AI's role and required output) and a user prompt (the actual gathered data), built differently depending on whether the target is an open-source repo or a piece of freeware.

3 System Prompt (identical for both flows)

This is the exact instruction block sent as the "system" role to the model:

You are a senior cybersecurity expert conducting a formal software security assessment. The findings below have already been filtered — all false positives and noise have been removed by a separate triage step. Every finding you see is confirmed or plausibly relevant to this specific software. Your task is exclusively to assess risk and produce actionable recommendations. Do NOT re-filter or second-guess the findings — they are clean. Respond ONLY with a valid JSON object, no markdown fences, no preamble. Required keys: risk_level (LOW/MEDIUM/HIGH/CRITICAL), verdict (Safe to use / Use with caution / Avoid), explanation (4-6 sentences: repo trust, CVE severity, dep risk, exploit availability, and web signals — be specific, cite CVE IDs and package names), attack_surface (array of specific attack vectors found), recommendations (array of concrete, prioritised remediation steps). Optional keys if in prompt: license_verdict, bundleware_risk.

Note: this system prompt tells the model the data has already been "filtered for noise," which technically isn't happening right now since Call 1 is bypassed (see section 2). The model is still receiving 100% of the raw findings, just labelled as pre-cleaned.

Call settings: max_tokens=2048, temperature=0.1 (low temperature = consistent, less "creative" output), 60-second timeout. The prompt is truncated at a section boundary if it exceeds ~20,000 characters, so the model never receives a half-cut-off entry.

3.2 User Prompt — Open Source Flow

Built by build_prompt_opensource(). This is what actually gets filled in and sent to the model as the "user" message when analyzing a GitHub/Bitbucket repo. The structure is:

=== OPEN SOURCE SECURITY ASSESSMENT ===
Tool: <tool name>
You are a senior application security engineer.
Assess the security and trustworthiness of this open-source repository.
Focus on: code supply chain risk, maintainer trust, license implications, exploitability.

[SECTION 1] REPOSITORY TRUST & AUTHENTICITY
  URL, stars, forks, watchers, contributors, archived/fork status,
  last pushed date, language, topics, README/SECURITY.md/CODEOWNERS
  presence, CI/CD workflows, plus up to 6 risk-flag warnings

[SECTION 1b] LICENSE SIGNIFICANCE
  License name, category, license risk level, what it allows,
  what it restricts, and a plain-English note

[SECTION 2] CVE / ADVISORY FINDINGS
  Sources used, totals by severity (CRITICAL/HIGH/MEDIUM/LOW),
  then up to 15 individual CVEs with severity, CVSS score, source,
  publish date, and a short description

[SECTION 3] DEPENDENCY VULNERABILITY ANALYSIS
  Packages scanned, vulnerable count, dependency files found,
  then up to 10 vulnerable packages with severity, name, version,
  CVSS score, direct/transitive flag, pinned/unpinned flag, and issue summary

[SECTION 4] DEEP WEB INTELLIGENCE (OS flow)
  Number of queries run, security hit count, sources used
  (GitHub repos/issues, DuckDuckGo, Exploit-DB, OSS Index),
  then up to 8 individual alarming findings

[INSTRUCTIONS]
Assess based on ALL sections above.
Consider: Is the repo actively maintained? Does the license create
legal/compliance risk? Are CVEs actively exploited or only theoretical?
Are dependencies up-to-date? Does web intel show public exploits or
threat actor activity?

Respond with ONLY this JSON (no markdown, no extra text):
{"risk_level":"LOW|MEDIUM|HIGH|CRITICAL",
 "verdict":"Safe to use|Use with caution|Avoid",
 "explanation":"3-5 sentences covering repo trust, license risk, vuln status, and web signals",
 "attack_surface":["item1","item2","item3"],
 "recommendations":["item1","item2","item3"],
 "license_verdict":"One sentence on license suitability for enterprise/commercial use"}
3.3 User Prompt — Freeware Flow

Built by build_prompt_freeware(). This is what gets sent to the model when analyzing a named freeware tool. The structure is:

=== FREEWARE SECURITY ASSESSMENT ===
Tool: <tool name>
You are a senior malware analyst and security engineer.
Assess the safety of this freeware application for enterprise and personal use.
Focus on: binary safety, malware/adware/bundleware, CVE history, download reputation.

[SECTION 1] INSTALLER FILE SCAN RESULTS
  Installer URL, file SHA256 hash

  -- VirusTotal --
  Verdict, engines flagged / total engines (detection %), threat name,
  permalink, plus up to 5 individual engine results
  (or "VT scan unavailable: <reason>" if not run)

  -- Hybrid Analysis --
  Verdict, threat score (/100), classification, malware family,
  AV detection count, IOC domains/IPs, permalink
  (or "HA scan unavailable: <reason>" if not run)

[SECTION 2] KNOWN CVEs / VULNERABILITIES (name-based lookup)
  Totals by severity, then up to 10 individual CVEs with
  severity, CVSS score, and description

[SECTION 3] DEEP WEB REPUTATION (freeware flow)
  Number of queries run, security hit count, sources used
  (DuckDuckGo, GitHub, MalwareBazaar), then up to 8 alarming findings

[INSTRUCTIONS]
Assess based on ALL sections above for freeware safety.
Consider: Is the installer clean per VT and HA? Does it bundle
adware/toolbars/PUPs? Are there known CVEs exploited in the wild?
Does web reputation show user complaints? Is it safe to install in
an enterprise environment? What are the privacy risks?

Respond with ONLY this JSON (no markdown, no extra text):
{"risk_level":"LOW|MEDIUM|HIGH|CRITICAL",
 "verdict":"Safe to use|Use with caution|Avoid",
 "explanation":"3-5 sentences covering binary scan results, CVE history, web reputation, and bundleware risk",
 "attack_surface":["item1","item2","item3"],
 "recommendations":["item1","item2","item3"],
 "bundleware_risk":"LOW|MEDIUM|HIGH — one sentence on adware/PUP/bundleware likelihood"}
 
4. How the AI's response is used
The script requires the response to be pure JSON — no markdown code fences, no extra commentary. There's a parser (parse_llm_json) that strips out backticks/preamble if the model adds them anyway, since models don't always follow "no markdown" perfectly.
If the model's response can't be parsed as valid JSON, or if all three models in the fallback chain fail (rate-limited, invalid key, or error), the script does not crash — it falls back to a default "unknown risk" result:
risk_level: "UNKNOWN"
verdict: "LLM unavailable"
explanation: "Assessment LLM call failed. Review findings manually."
recommendations: ["Review CVE findings manually", "Check GROQ_KEY at console.groq.com"]
Whatever the model returns (or the fallback above) becomes the risk_level, verdict, explanation, attack_surface, recommendations, and license_verdict/bundleware_risk fields in both the console summary and the final JSON/PDF report.


---
**OS/FT Analyzer (OSTE.py) — API Endpoints Reference**

This lists every external API endpoint the OS/FT Analyzer script calls, grouped by purpose. For each endpoint: what it's used for, which phase of the script calls it, the HTTP method, and whether it needs an API key.

1. GitHub API — Repository Trust & Authenticity

Used to establish how trustworthy and actively maintained an open-source repository is, and to search for security-related issues about it.

Endpoint	Method	Purpose	Auth
https://api.github.com/repos/{owner}/{repo}	GET	Core repo metadata — stars, forks, watchers, open issues, license, language, topics, fork/archived status, default branch, created/pushed dates	Optional GITHUB_TOKEN (raises rate limit)
https://api.github.com/repos/{owner}/{repo}/contributors	GET	Contributor count and top 5 contributors by commits	Optional GITHUB_TOKEN
https://api.github.com/repos/{owner}/{repo}/commits	GET	Recent commit history (last 30 commits)	Optional GITHUB_TOKEN
https://api.github.com/repos/{owner}/{repo}/releases	GET	Latest release info	Optional GITHUB_TOKEN
https://api.github.com/repos/{owner}/{repo}/zipball/{branch}	GET	Downloads full repo source (zip) via authenticated API — used for dependency-file tree walk	Requires GITHUB_TOKEN
https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip	GET	Fallback: downloads repo source zip via public (unauthenticated) URL if no token or API path fails	None
https://github.com/{owner}/{repo}/zipball/{branch}	GET	Second fallback: public zipball redirect URL	None
https://api.github.com/repos/{owner}/{repo}/issues	GET	Checks the target repo's own open issues labelled "security"	Optional GITHUB_TOKEN
https://api.github.com/search/repositories	GET	Searches GitHub globally for exploit/PoC repos or malware-analysis repos referencing the tool name	Optional GITHUB_TOKEN
https://api.github.com/search/issues	GET	Searches GitHub globally for issues mentioning the tool name alongside CVE/RCE/injection/bypass keywords	Optional GITHUB_TOKEN
https://api.github.com/advisories	GET	Queries GitHub Security Advisories (GHSA) database — first by precise package coordinate (affects=), then by free-text keyword search as a fallback	Optional GITHUB_TOKEN (keyword search only runs if a token is present, to avoid burning rate limit)

Without a GITHUB_TOKEN, GitHub enforces a low unauthenticated rate limit — the script will warn in the console if it gets rate-limited.

2. Vulnerability / CVE Databases

Used to find known vulnerabilities affecting the project itself and its dependencies.

Endpoint	Method	Purpose	Auth
https://services.nvd.nist.gov/rest/json/cves/2.0	GET	National Vulnerability Database — keyword search for CVEs tied to the project name (paginated)	Optional NVD_API_KEY (raises rate limit / reduces required delay between calls)
https://api.osv.dev/v1/querybatch	POST	OSV.dev — batched vulnerability lookup by package name/ecosystem/PURL, used both for the main project and for every dependency package found	None
https://api.osv.dev/v1/vulns/{id}	GET	OSV.dev — fetches full detail for each individual vulnerability ID returned by the batch query (fetched concurrently, capped at 30 per run)	None
https://api.first.org/data/v1/epss	GET	EPSS (Exploit Prediction Scoring System) — returns the probability that a given CVE will actually be exploited in the wild, used to prioritise findings	None
3. Dependency / Package Reputation

Used during the dependency-tree scan (open-source flow only) to check whether individual packages a project depends on are risky.

Endpoint	Method	Purpose	Auth
https://api.snyk.io/v1/test/{ecosystem}/{package}/{version}	GET	Snyk vulnerability database — checked for each dependency package found to be at risk	Requires SNYK_TOKEN (skipped if not set)
https://ossindex.sonatype.org/api/v3/component-report	POST	Sonatype OSS Index — the same vulnerability database used behind Snyk/OWASP Dependency-Check; free alternative used when Snyk isn't available	None
4. Web Search / General Reputation

Used to search the open web for reviews, advisories, and red-flag mentions of the tool. All routed through DuckDuckGo's HTML search endpoint (no API key, no official rate limit, since it scrapes the public search-results page rather than using a paid search API).

Endpoint	Method	Purpose	Auth
https://html.duckduckgo.com/html/	GET	General-purpose web search, reused with different queries across the script for:
• Open-source flow: security-relevant mentions of the project
• Freeware flow: malware/adware/bundleware/spyware/trojan mentions, general trustworthiness reviews, privacy/data-collection concerns, and a site-scoped search of exploit-db.com
• Dependency scan: per-package "is this vulnerable" reputation check	None
5. Malware & Threat Intelligence Feeds (abuse.ch)

Used in the freeware flow to check whether the tool name/domain is already known to malware-tracking community databases.

Endpoint	Method	Purpose	Auth
https://mb-api.abuse.ch/api/v1/	POST	MalwareBazaar — checks if any known malware sample is tagged with the tool's name	None
https://bazaar.abuse.ch/browse.php	—	MalwareBazaar web browse link (reference/display URL, not queried directly)	None
https://urlhaus-api.abuse.ch/v1/payload/	POST	URLhaus — checks if the tool's name/domain appears in the active phishing/malware-payload database	None
https://urlhaus.abuse.ch/browse.php	—	URLhaus web browse link (reference/display URL, not queried directly)	None
6. File Scanning — Installer Malware Analysis (Freeware flow only)

Used only when a direct installer download URL is supplied. The script downloads the file itself, then submits/checks it against these two scanners.

VirusTotal
Endpoint	Method	Purpose	Auth
https://www.virustotal.com/api/v3/files/{sha256}	GET	Hash pre-check — if VT already has a scan result for this exact file, return it instantly without uploading	Requires VT_API_KEY
https://www.virustotal.com/api/v3/files/upload_url	GET	Requests a one-time upload URL (used for large files)	Requires VT_API_KEY
https://www.virustotal.com/api/v3/files	POST	Uploads the installer file for scanning (used when no existing record was found)	Requires VT_API_KEY
https://www.virustotal.com/api/v3/analyses/{id}	GET	Polls the status of an in-progress scan until it completes	Requires VT_API_KEY
https://www.virustotal.com/gui/file/{sha256}	—	Public web report link included in the output report (reference URL, not queried)	None
Hybrid Analysis
Endpoint	Method	Purpose	Auth
https://www.hybrid-analysis.com/api/v2/search/hash	GET	Hash pre-check — checks if this file has already been analyzed	Requires HA_API_KEY
https://www.hybrid-analysis.com/api/v2/submit/file	POST	Submits the installer file for full sandbox/behavioural analysis	Requires HA_API_KEY
https://www.hybrid-analysis.com/api/v2/report/{job_id}/state	GET	Polls whether the sandbox analysis job has finished	Requires HA_API_KEY
https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary	GET	Retrieves the summary of a completed sandbox report	Requires HA_API_KEY
https://www.hybrid-analysis.com/api/v2/overview/{sha256}	GET	Retrieves an overview report by file hash	Requires HA_API_KEY
https://www.hybrid-analysis.com/api/v2/quick-scan/file	POST	Submits the file for a faster "quick scan" (lighter than the full sandbox submit)	Requires HA_API_KEY
https://www.hybrid-analysis.com/api/v2/quick-scan/{scan_id}	GET	Polls the status/result of a quick scan	Requires HA_API_KEY
https://www.hybrid-analysis.com/sample/{sha256}	—	Public web report link included in the output report (reference URL, not queried)	None

7. LLM — Risk Assessment

Used to triage findings and produce the final human-readable risk verdict.

Endpoint	Method	Purpose	Auth
https://api.groq.com/openai/v1/chat/completions	POST	Called twice per run: (1) triage/noise-filter pass over raw findings, currently bypassed/pass-through in this version, and (2) the main security assessment call that produces risk level, verdict, explanation, attack surface, and recommendations	Requires Groq API key 

8. Reference-Only Links (not called, shown in reports for humans to click)

These URLs appear in the JSON/PDF output as clickable references but are never fetched by the script itself:

URL pattern	Where it's used
https://nvd.nist.gov/vuln/detail/{cve_id}	Link to the NVD detail page for each CVE found
https://osv.dev/vulnerability/{id}	Link to the OSV.dev detail page for each vulnerability found
https://security.snyk.io/package/{ecosystem}/{package}	Link to the Snyk advisory page for a vulnerable dependency
https://ossindex.sonatype.org/component/{purl}	Link to the OSS Index page for a vulnerable dependency
Summary — Keys Required for Full Functionality
Key / Env Var	Required for	If missing
GITHUB_TOKEN	Higher GitHub API rate limits, private repo zip download, GHSA keyword search	Falls back to public rate limits; keyword-based GHSA search is skipped
NVD_API_KEY	Faster/higher-volume NVD queries	Falls back to slower public rate limit (longer delay between calls)
SNYK_TOKEN	Per-package Snyk vulnerability lookups	Snyk check is skipped; OSS Index is used instead
VT_API_KEY	VirusTotal file scanning key is used (see note below)
HA_API_KEY	Hybrid Analysis file scanning key is used (see note below)
Groq key	LLM triage + risk assessment; if the call fails, script still runs but marks risk as "UNKNOWN"
