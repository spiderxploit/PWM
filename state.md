# PWM — Session State

## Current Status: ALL FIXES VERIFIED
- Recon run-all works: single `approve_stage recon` launches all 7 substages.
- Clean-target recon yields only the 5 REAL localhost listeners (verified against `ss -tln`): 5000 (PWM), 9050 (Tor), 11434 (Ollama), 55027 (Spotify), 57621 (Spotify helper) — accurate, not noise.
- PDF PoC/Remediation: Courier-Bold, dark text (#1f2328) on light bg (#f6f8fa), bordered — visible/readable. Real detection command embedded (was "# No detection command recorded").
- Root tools: recon_ports no longer requires root (auto scan type); recon_udp tries `sudo -n`, else fallback.

## App Facts
- `app.py` at repo root; `frontend.html` served via `send_file` (no templates/ dir).
- **ALWAYS use `venv/bin/python3` (user requirement — never bare `python`).** `venv/bin/python3` → /usr/bin/python3 but picks up venv site-packages (reportlab).
- Run: `setsid nohup venv/bin/python3 app.py </dev/null > /tmp/pwm_server.log 2>&1 & disown; sleep 3`
- Restart: `PID=$(ss -tlnp | grep ':5000' | grep -oP 'pid=\K[0-9]+' | head -1); kill $PID`. **Never `pkill -f app.py`** (kills invoking shell).
- Test: `make_cmd()` + `dispatch_parser()` in-process via `venv/bin/python3 - <<EOF`; live via `/api/session/<sid>/stream` SSE → `/tmp/pwm_sse*.txt`.
- Restart wipes in-memory sessions — always create a fresh SID after restart.

## Changes This Session (requested fixes)
1. **python3**: all commands now `venv/bin/python3`.
2. **Root tools fixed**:
   - `recon_ports`: dropped `-sS`/`-O` (root-only), removed `requires_root`. nmap auto-selects SYN (root) / connect (non-root). Description updated.
   - `recon_udp`: keeps `requires_root`; `execute_substage` now tries `_sudo_available()` (`sudo -n true` probe, cached) → prefixes `sudo -n`; else falls back to `fallback_cmd`.
   - `_raw_bin` extraction skips leading `sudo` for the tool-exists check.
3. **No-hallucination fixes**:
   - `infer_network`: no longer fabricates `192.168.1.0/24` for non-CIDR targets — returns target itself. Frontend preview placeholder for `{network}` changed to `d.target` (was hardcoded 192.168.1.0/24).
   - `parse_generic`: skip `;;`-prefixed lines (dig diagnostics like `;; communications error to 192.168.1.1#53` matched keyword "error").
   - `parse_waf` (new, used by recon_waf_cdn): reports ONLY real WAF/CDN detections ("is behind", vendor+WAF context). Kills wafw00f ASCII-banner FPs ("404 Hack Not Found" matched keyword "found"). NOTE: ANSI-strip filter in parse_generic is a no-op live because `run_command` strips ANSI before parsing — parse_waf is the real fix.
   - PDF PoC block: removed fabricated "# Verification / Confirm finding exists" boilerplate.
4. **Run-all substages button (recon)**: button now shown for ALL stages; backend `approve_stage` launches every substage regardless of `parallel` flag (was serial: only subs[:1]). Frontend `.show` added for all stages.
5. **PDF PoC/Remediation visible**: `CODE` style now Courier-Bold 8.5, text #1f2328 on #f6f8fa, border #d0d7de, borderPadding 8, leading 13. New `SEC` style for section titles (Helvetica-Bold 10, blue).
6. **Real command in PDF**: `sess['commands'][sub_id]` now stored in `execute_substage`; `build_pdf` falls back to it when a finding lacks `command` (open_port findings had none → placeholder text).
7. **No timeouts + UDP fallback fixed**: all timing flags removed from templates (`timeout N`, `--max-time`, `-timeout`, `--timeout=`, `nc -w`). `recon_udp` fallback_cmd replaced the non-runnable skip-echo with an in-band `python3 -c` socket probe (send empty datagram → open on reply, open|filtered on timeout, closed on ICMP port-unreachable) printing nmap-format lines so `parse_nmap` picks up real open UDP ports. Verified against a live local UDP listener (5353 → `5353/udp open mdns`).
8. **recon_osint theHarvester fixed**: `-b google,bing,...` was a real CLI error — theHarvester 4.11.1 removed `google`/`bing` sources and exits rc=1 with `[!] Invalid source.` (confirmed live). Replaced with valid no-key sources: `baidu,yahoo,dnsdumpster,certspotter,crtsh,hackertarget,rapiddns` (verified rc=0 live).
 9. **Recon phase CLI audit**: all 7 recon substage commands executed end-to-end against real targets — `recon_ports` (nmap -sV -sC), `recon_udp`, `recon_dns` (dig/host/dnsrecon std,axfr,brt), `recon_web` (curl/whatweb/wafw00f), `recon_smb` (nmblookup/smbclient/rpcclient/enum4linux), `recon_osint` (whois/crt.sh/theHarvester), `recon_waf_cdn` — only theHarvester had a CLI error; all others run clean. Slow runs (dnsrecon brt, whatweb -a 3, enum4linux) are expected now that timings are removed.
10. **Recon hang fixes (this session)**: 3 substages never finished against example.com. Root causes + fixes, all measured live:
   - `recon_ports`: `nmap -sV -sC -p-` hung >90s — the `-sC` scripts hang on the open `8080 http-proxy` port. Now two-phase: `nmap -p- --min-rate 10000 -T5 --open -oG` (~15s) then `nmap -sV --version-light --max-retries 1 -p <PORTS>` (~16s). Drops `-sC` (info covered by recon_smb/recon_web). Output format switched to `-oG nmap_full.gnmap` (was `-oN nmap_full.txt`). **Total 32s, rc=0**; `parse_nmap` still finds all open ports. Fallback: `-sV --version-light` on common ports.
   - `recon_dns`: `dnsrecon -t std,axfr,brt` hung — `brt` brute-force runs forever. Dropped `brt` → `-t std,axfr`. **Total 36.6s, rc=0**. Description updated (removed brute-force claim).
   - `recon_web`: curl to filtered `:8443` waited full kernel TCP timeout (~130s) after timings were removed. Re-added curl `--max-time 8` — this is per-request connection bound (NOT a scan-killing wrapper; long scanners nmap/dnsrecon/whatweb/enum4linux stay unbounded). Also `whatweb -a 3` → `-a 1`. **Total 25.3s, rc=0** (was 109s).
   - Applied `--max-time 8` to all target-facing curl in `recon_osint` (crt.sh) and `recon_waf_cdn` too: 19.2s / 18.3s, rc=0.
   - After fixes all 6 live-run recon substages FINISH with rc=0 and parse cleanly.
11. **Recon stage stuck at 43% (this session)**: user reported `recon_udp`, `recon_web`, `recon_osint`, `recon_waf_cdn` never complete → recon stage freezes at 3/7 = 43%. 43% = per-stage bar (`done/subs` in frontend.html `updateStageProg`), not a kill. Root cause: `run_command` waits on `proc.wait()` forever (PWM_CMD_TIMEOUT=0), and those 4 chains contain tools with unbounded adverse-case wall time:
   - **`whatweb` HANGS >60s on accept-but-never-respond targets** (reproduced: stall server on 8081; its 15s open / 30s read timeouts apply per plugin request and stack). CONFIRMED the only true infinite hang.
   - `wafw00f` (7s client timeout per request), `nmap` WAF scripts, `theHarvester` (7 sources), `whois`, `nmap -sU` top-15 — all finish but can stretch to minutes on hostile/filtered targets.
   - Fix: GNU `timeout -k 5 <sec>` wrappers at generous caps (well above measured legit runs): whatweb 60 (legit 6s), wafw00f 45 (legit ~7s), whois 30 (legit 6s), theHarvester 120 (legit 20s), nmap WAF NSE 60 (legit 3s), nmap -sU 90. Long scans (recon_ports full port, dnsrecon, enum4linux, deep-stage) remain unbounded.
   - Verified: recon stage end-to-end vs hostile blackhole target (192.0.2.1) completes **7/7 in 58s**; whatweb unit test vs stall server now exits at exactly 60s rc=124 instead of hanging forever.
12. **crt.sh tool integration (this session)**: user installed `/usr/bin/crt.sh` (az7rb crt.sh v2.0, a curl+jq wrapper — 7-line banner, `-d <domain>` / `-o <org>`, writes `output/domain.<dom>.txt` relative to CWD, requires jq). `recon_osint` now uses it: `case {target} in *[a-zA-Z]*) if command -v crt.sh...; then (cd {outdir} && timeout -k 5 60 crt.sh -d {target}) 2>/dev/null | tail -n +8 | head -80; else <curl fallback>; fi;; *) echo skipped-IP;; esac`. Details: 60s GNU cap (the tool's internal curl has NO --max-time → unbounded without it), `2>/dev/null` hides jq parse-error noise when service returns HTML, `tail -n +8` strips the fixed 7-line banner, `(cd {outdir} && ...)` keeps the `output/` file side effect out of the app dir, IP targets skip (tool is domain-only). Note: there is a SECOND copy at `/home/icognito/Tools/crt.sh/crt.sh` NOT on PATH — PATH resolves `/usr/bin/crt.sh`, which is the integrated one. **crt.sh service is currently DOWN (502 Bad Gateway on all endpoints as of this session)** so the tool reports "No valid results found." until it recovers — verified both hostname (runs tool) and IP (skips) paths through `run_command`; py_compile clean.

## Verified Live Run
- SID `1ad4cb0b-b5e5-41cd-99e8-94ddc83c8190` (current, clean 127.0.0.1): recon 7/7, only 5 real open ports. PoC page rendered to `/tmp/pwm_poc_page.png`.
- Full chain 22/22 zero-finding run (pre-this-session): SID `39066ee6...`.

## Prior Completed Work (context retained)
- `make_cmd` regex rewrite (~line 504): unknown placeholders (`%{http_code}` etc.) left intact — no `%127.0.0.1` mangling.
- Timeout logic: `PWM_CMD_TIMEOUT=0` default (no app timeout). No timing flags anywhere in templates — all `timeout N` wrappers, curl `--max-time`, nuclei `-timeout`, sqlmap `--timeout=`, and `nc -w` removed so scans never get killed early. UDP probe keeps a 1s socket timeout (functionally required: UDP `recv` would block forever otherwise). **UPDATE (entry 10): curl `--max-time 8` was re-added to target-facing curl only** — without it, curl to a filtered port waits the kernel TCP timeout (~130s) and the substage never finishes. Long scanners remain unbounded.
- Parallel-stage approve; queue memory safety (maxsize 20000, drop-oldest, 6h janitor).
- `frontend.html`: STAGE_NUMS fixed; `appendOut()` class bug fixed.
- Parser FP fixes: SSRF closed-port (000/403 excluded), rate-limit 000 filter, Mongo regex tightened, weak-cipher signature context-anchored, signature scan uses parse_output (cmd-echo stripped), parse_output strips first `$ ` line.

## Next Steps
- Run vuln/deep/exploit_prep/postex stages on a clean target to confirm zero-FP across remaining stages.
- Clean up /tmp/pwm_* test artifacts.
