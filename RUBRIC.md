# App Risk Auditor — Scoring Rubric (PS-01)

Score = special access + categories 02–09 + combination/context rules, clamped to **0–100**.
Every point comes with a plain-language reason. Source of truth: `RiskEngine.java`.

**Bands:** Low 0–24 · Medium 25–49 · High 50–74 · Critical 75–100.
High/Critical apps always show at least 3 reasons.

## 1. Special access (highest weight, category cap 45)
Read from live system state (Settings.Secure, DevicePolicyManager, AppOpsManager).

| Access | Enabled / granted | Declared only |
|---|---|---|
| Accessibility service | 30 | 10 |
| Device admin | 25 | 8 |
| Notification listener | 20 | 7 |
| Draw over apps (SYSTEM_ALERT_WINDOW) | 15 | 6 |
| Install other apps (REQUEST_INSTALL_PACKAGES) | 12 | 5 |
| Usage access (PACKAGE_USAGE_STATS) | 8 | 3 |

## 2. Permission categories 02–09
Granted = full points. Declared but not granted = 40 %. Each category is capped.

| # | Category | Main weights | Cap |
|---|---|---|---|
| 02 | SMS | READ_SMS 15, RECEIVE_SMS 12, SEND_SMS 12 | 25 |
| 03 | Contacts & call logs | READ_CALL_LOG 12, READ_CONTACTS 8, PROCESS_OUTGOING_CALLS 8 | 15 |
| 04 | Camera & microphone | CAMERA 8, RECORD_AUDIO 8 | 12 |
| 05 | Location | BACKGROUND 10, FINE 6, COARSE 3 | 12 |
| 06 | Phone & identity | CALL_PHONE 6, READ_PHONE_NUMBERS 5, READ_PHONE_STATE 4 | 10 |
| 07 | Storage & media | MANAGE_EXTERNAL_STORAGE 10, READ_MEDIA_IMAGES 4, READ_EXTERNAL_STORAGE 4 | 10 |
| 08 | Background & persistence | IGNORE_BATTERY_OPTIMIZATIONS 6, BOOT_COMPLETED 4, FOREGROUND_SERVICE 2 | 8 |
| 09 | Network | INTERNET 1, ACCESS_NETWORK_STATE 1 | 2 |

## 3. Combination rules
| Rule | Points |
|---|---|
| SMS read/receive + INTERNET + BOOT_COMPLETED + sideloaded (banking-trojan pattern) | +25 |
| Accessibility (enabled or declared) + overlay | +25 |
| Device admin on an app that isn't a security / MDM tool (active / declared) | +20 / +10 |
| Notification listener enabled + INTERNET (OTP exfiltration) | +10 |
| REQUEST_INSTALL_PACKAGES + sideloaded + INTERNET (dropper) | +10 |

## 4. Context and source rules
| Rule | Points |
|---|---|
| Context mismatch: torch / calculator / wallpaper / QR / cleaner-type name, or Game/Photo/Audio/Video Play category, holding SMS, contacts, call log, accessibility, device admin or notification access | +20 |
| Update added new sensitive permissions (permission diff) | +10 |
| Target SDK < 23 (gets dangerous permissions without asking) | +10 |
| Sideloaded (installer is not a known app store) | +5 |
| Debuggable build | +5 |
| Cleartext traffic allowed + INTERNET | +3 |
| ≥ 5 exported services/receivers/providers without a permission | +3 |
| User app with no launcher icon (hidden), excluding keyboards and accessibility tools | +8 |
| Pre-installed system app | total × 0.6 |

Trusted installers: Google Play, Galaxy Store, Amazon, Huawei, Xiaomi, Oppo/Heytap, Vivo, F-Droid, Aurora.

## 5. AI model (shown beside the score, not added to it)
TFLite network from projectmatris/antimalwareapp on 2000 permission + intent features.
> 75 % Malware-like · > 50 % Suspicious · else Looks safe. Flagged as "AI and rules disagree" when
the model says > 75 % but the rules say Low/Medium, or < 20 % while the rules say Critical.
Install monitoring also alerts on any app the model rates > 75 %.

## 6. Network monitor findings (only when the monitor has run)
| Seen contacting | Points |
|---|---|
| Bot / paste / tunnel service (api.telegram.org from a non-Telegram app, ngrok, pastebin, webhook.site …) | +15 |
| Free dynamic DNS / throwaway TLD (duckdns, no-ip, .tk/.ml/.ga/.cf/.gq …) | +12 |
| Random-looking (DGA-style) domain | +8 |
| Reads SMS **and** contacts a bot/paste/tunnel service (OTP-stealer pattern) | +15 |
| Ad / tracking SDK servers | 0 (shown only) |

## 7. File scanner severities (separate from app scores)
| Severity | Examples |
|---|---|
| Critical | disguised executables / APKs, right-to-left-override names, auto-run or downloading macros, Follina links, PDF /Launch or auto-run JavaScript, RTF Equation Editor objects, scripts that download-and-run, trojan-pattern APKs, AI > 75 %, EICAR |
| High | Windows programs, native binaries, DEX, .lnk, Windows scripts, VBA macros, remote templates, DDE, PDF JavaScript, APKs needing special access, password-protected ZIPs holding programs, phishing pages |
| Medium | APK installers, macro-capable file types, embedded objects, password-protected archives/Office files, shell scripts |
| Info | archives that can't be opened, clean files |
