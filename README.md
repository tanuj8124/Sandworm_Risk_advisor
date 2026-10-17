# App Risk Auditor — PS-01 On-Device App Risk Auditor
-----------------------------------------------------
Android app that scans installed apps on the device, sorts their permissions and special access
into the nine PS-01 categories, and gives each app an explainable 0–100 risk score.

* **Q1 Which apps can do the most harm?** Home screen: apps sorted by score, Critical/High/Medium/Low filter chips, device-wide category summary.
* **Q2 Why is each one flagged?** Detail screen "Why flagged" panel: every reason in plain language with its points.
* **Q3 What can I do right now?** One-tap buttons straight to the right settings screen (accessibility, device admin, notification access, overlay, unknown sources, usage access, all-files), app settings, and Uninstall.

No root, no ADB for the end user, everything runs on the phone and the core features work offline.

## Build (Android Studio)
1. Open this folder in Android Studio (Ladybug or newer, JDK 17). Let Gradle sync.
2. **Build ▸ Build APK(s)** → `app/build/outputs/apk/debug/app-debug.apk`
   or from a terminal: `./gradlew :app:assembleDebug`
3. Install: `adb install -r app/build/outputs/apk/debug/app-debug.apk`

The harmless test target lives in `testapp/` ("Super Torch"): `./gradlew :testapp:assembleDebug`, install it,
and it should score **Critical** on the rules and ≈ 98 % on the AI model. It only *declares* risky permissions
and no-op components; it has no working code.

## Requirement coverage
| # | Requirement | Where |
|---|---|---|
| 01 | Inventory (name, icon, package, version, install date, installer, target SDK, system toggle) | `AppScanner`, `MainActivity`, `DetailActivity` |
| 02 | Declared vs granted + protection level | `AppScanner.build / protectionOf` |
| 03 | Nine categories per app + device-wide summary | `PermissionCatalog`, home summary card |
| 04 | Accessibility / device admin / notification listener / overlay / install-packages | `AppScanner.readSystemState`, AppOps |
| 05 | 0–100 score, 4 bands, ≥3 reasons for High/Critical | `RiskEngine` |
| 06 | Why-flagged panel, settings button, uninstall button | `DetailActivity` |
| 07 | Combination rules | `RiskEngine` |
| 08 | Context mismatch | `RiskEngine.contextMismatch` |
| 09 | Install monitoring + notification | `MonitorService`, `Notifier`, `BootReceiver` |
| 10 | Permission diff on update | `SnapshotStore` |
| 11 | SHA-256 hash + optional lookup (hash only, after consent) | `DetailActivity`, `AppScanner.sha256` |
| 12 | Static checks: debuggable, cleartext, exported components | `AppScanner`, `RiskEngine` |
| 13 | On-device ML model shown beside the rule score | `MlScanner`, `ManifestReader` |
| 14 | PDF report export | `PdfReport` |
| + | Component explorer, hidden-icon detection | `ComponentsActivity`, `ManifestReader` |
| + | Network monitor (DNS per app) | `NetMonitorService`, `DnsPacket`, `DomainIntel`, `NetworkActivity` |
| + | File scanner + live download watching | `FileAnalyzer`, `FileScanner`, `FileWatcher`, `FileScanActivity` |

## Component explorer
Detail page → **Show all components**: every activity, service, broadcast receiver and content provider,
whether it is *open* (exported) to other apps, which permission protects it, which intent actions wake it up,
and plain-language flags ("is woken up by every incoming SMS", "any app can read its data"). Risky ones are listed first.
Apps with **no launcher icon** (hiding from the app drawer) get +8 on the risk score.

## Network monitor
Home → **Network monitor**. A local VPN that captures **only DNS lookups** (the VPN routes a single fake DNS
address, all other traffic goes out untouched), attributes each lookup to the app that made it
(Android 10+), and flags:
* message-bot / paste / tunnel services used to send stolen data out (e.g. `api.telegram.org` from a non-Telegram app, ngrok, pastebin),
* free dynamic-DNS and throwaway domains (duckdns, no-ip, .tk …),
* random-looking (DGA-style) domain names,
* ad/tracking SDK servers (informational only).

Suspicious finds raise an alert, add points to that app's score, and show on its detail page and in the PDF.
Reads only server names, never traffic content, and stores everything on the phone.
Limitations: needs Private DNS set to Automatic/Off (the app warns you), can't run alongside another VPN,
and apps with their own DNS-over-HTTPS bypass it.
For the demo, open the test app and tap **"Demo: look up api.telegram.org"**: the alert fires straight away.

## File scanner
Home → **File scanner**. Checks what each file *really* is (header bytes and internal structure), not just its name:

| Finds | Example |
|---|---|
| Windows programs, native binaries, loose DEX code | `setup.exe`, ELF files in Downloads |
| Disguised files | `invoice.pdf.exe`, `.pdf` that is really an `.exe`, hidden right-to-left-override names |
| APK installers | permissions, special access, banking-trojan patterns **and the on-device AI verdict**, plus APKs renamed as photos |
| Office macros & exploits | VBA macros (old `.xls/.doc` and `.xlsm/.docm`), auto-run macros, remote template injection, Follina (`ms-msdt`/`mhtml`), DDE, embedded objects, password-protected Office files |
| Risky PDFs | JavaScript, auto-run actions, `/Launch`, embedded files (also catches `/J#61vaScript` obfuscation) |
| RTF exploits | Equation Editor objects (CVE-2017-11882) |
| Scripts | `.ps1/.vbs/.bat/.js/.hta/.lnk/.sh`, and code that downloads-and-runs (`IEX`, `-enc`, `certutil`, `curl … | sh`) |
| Archives | dangerous or disguised files inside ZIPs, password-protected ZIPs |
| Phishing pages | saved HTML with password forms that post online, HTML smuggling |
| Test file | the standard **EICAR** antivirus test file |

Three ways to scan: **whole phone storage** (needs "All files access"), **pick files**, or **pick a folder** (no broad permission).
**Live watching** of Download, Documents, Bluetooth, WhatsApp and Telegram folders checks each new file as it arrives
(Hypatia's real-time file-observer idea) and alerts on High/Critical. Each result offers **Delete** and an optional
**hash check** (only the SHA-256 is sent, after consent).

Demo: tap **"Create harmless EICAR test file in Downloads"** with live watching on and the alert pops up.
More practice files: `python3 tools/make_test_samples.py` creates harmless samples to copy to the phone.

## AI model (requirement 13)
Uses the TensorFlow Lite model and `features.json` from
[Project Matris AntiMalwareApp](https://github.com/projectmatris/antimalwareapp) (GPL-3.0), stored in
`app/src/main/assets/malware_model.tflite` and `malware_features.json`.

* **Input:** 2000 values (0 or 1): 489 permissions followed by 1511 intent-filter actions found in the app's manifest.
* **Network:** 2000 → 32 (ReLU) → 1 (sigmoid) = malware probability.
* **Verdict:** > 75 % Malware-like · > 50 % Suspicious · otherwise Looks safe (same thresholds as the original app).
* Shown as a separate "AI %" next to every rule score, an "AI model check" card on the detail page, in alerts and in the PDF.
  The **rule score still produces all the explanations**; if the two strongly disagree the app says so.
* Intent actions are read by `ManifestReader`, which decodes the APK's binary manifest directly.
  The original app used the hidden `AssetManager.addAssetPath()` API, which newer Android blocks.
* Runs fully offline, no data leaves the phone.

The only use of the INTERNET permission is the optional network monitor passing other apps' DNS lookups
on to the phone's normal DNS server (which those lookups would reach anyway).

Sanity check of the model with its own weights (numpy, outside Android):
a trojan-like manifest (SMS + boot receivers, overlay, install packages…) scores ≈ 98 %, a plain internet-only app ≈ 3 %.

## Demo tips
* Turn on "Watch new installs & updates" before the judges install the test kit; each new High/Critical app triggers a notification that opens its detail page.
* adb-installed apps show as **sideloaded** (installer = none / ADB shell).
* Dangerous permissions installed via `adb install` are *not granted* until the app asks, so they count at 40 %. `adb install -g` grants them all.

