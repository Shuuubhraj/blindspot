# Blindspot synthetic test fixtures - expected-scan documentation

Fixtures live in `backend/tests/fixtures/`:
- `make_fixture_apk.py` - generator script (re-run to rebuild the APK).
- `test-app.apk` - generated output. **Regenerate, don't hand-edit.**
- `vuln_app/` - 20 small Java source files with intentional (in)vulnerabilities.

> Everything here is synthetic. All secrets, keys, tokens, passwords, card
> numbers and certificates are invented placeholders (e.g.
> `AKIAIOSFODNN7EXAMPLE`, which follows the documented AWS *example* format).
> No real credentials exist anywhere in this tree.

## Regenerating

From `backend/`:

```bash
.venv/bin/python tests/fixtures/make_fixture_apk.py
```

The script builds the APK, then self-verifies: it re-reads
`AndroidManifest.xml` from the written zip, decodes it with
`blindspot.analysis.axml.parse_axml`, and asserts package, version,
SDK levels, the 7 permissions, application flags, and the exported
components round-trip. It also runs androguard 4.1.4 (when available in
`.venv`) as a second-opinion parse and prints `unzip -l` + SHA-256.

## `test-app.apk` contents

| Entry | Bytes (stored) | Content |
|---|---|---|
| `AndroidManifest.xml` | 4166 (binary AXML) | Real binary XML. Package `com.blindspot.testapp`, `versionCode=1`, `versionName="1.0"`, `minSdkVersion=21`, `targetSdkVersion=28`. Application: `debuggable=true`, `allowBackup=true`, `usesCleartextTraffic=true`, label `@string/app_name`. |
| `res/values/strings.xml` | 262 | Plain-text XML with `<string name="api_key">AIzaSyD-testkey-1234567890abcdef</string>` (synthetic). |
| `assets/private_key.pem` | 220 | **Fake** PEM: the body is a human-readable "FAKE TEST KEY - NOT REAL" label, not key material. |
| `lib/armeabi-v7a/libnative.so` | 64 | Dummy bytes, documented in the generator as not a real binary. |
| `META-INF/MANIFEST.MF` | 103 | Dummy manifest text. |

Manifest component inventory:
- `uses-permission`: `INTERNET`, `READ_SMS`, `SEND_SMS`, `READ_CONTACTS`,
  `ACCESS_FINE_LOCATION`, `CAMERA`, `RECORD_AUDIO`.
- `.MainActivity` - `exported=true`, **no** `android:permission`; intent-filter
  `VIEW` + `BROWSABLE` for `https://testapp.blindspot.example/applink` with
  **no** `android:autoVerify` attribute.
- `.DebugActivity` - `exported=true` (name contains "debug").
- `.SmsReceiver` - `exported=true`, **no** `android:permission`,
  intent-filter on `android.provider.Telephony.SMS_RECEIVED`.
- `.TestProvider` - `exported=true`, `grantUriPermissions=true`,
  authorities `com.blindspot.testapp.files`, **no** read/write permission.

Last verified build: 2234 bytes,
`sha256=d9a3eb9bb6057c7124ae8959705dde86e681260e783853830492bbbd921bc722`.
SHA will change if the generator changes; re-run the script for the
authoritative value.

## `vuln_app/` file inventory

| File | Intentional issue(s) | Should also catch |
|---|---|---|
| `HardcodedSecrets.java` | `API_PASSWORD` / `clientSecret` string literals; synthetic `AKIAIOSFODNN7EXAMPLE` AWS key | - |
| `WeakCrypto.java` | `MD5` hashing a password; `DES`; `AES/ECB/PKCS5Padding`; hardcoded `SecretKeySpec` key + `IvParameterSpec` IV; `java.util.Random` for a session token | - |
| `TrustAllCerts.java` | Empty `X509TrustManager` (trust-all); `ALLOW_ALL_HOSTNAME_VERIFIER`; `http://` endpoint | - |
| `WebViewBugs.java` | `setJavaScriptEnabled(true)`; `addJavascriptInterface`; `setAllowUniversalAccessFromFileURLs(true)` (+ file-access variant); `loadUrl("http://…")`; `onReceivedSslError` → `handler.proceed()` | - |
| `InsecureStorage.java` | `MODE_WORLD_READABLE` prefs; `Log.d` password; token file on external storage; password in `putExtra`; token on clipboard | - |
| `SqlInjection.java` | `rawQuery` with string concatenation | `lookupSafe()` parameterized - clean control |
| `CommandInjection.java` | `Runtime.getRuntime().exec("ping -c 1 " + host)` | - |
| `AuthBypass.java` | Hardcoded `admin`/`admin` bypass; hardcoded `test@test.com`/`test123` account; plaintext bearer token in `SharedPreferences` | - |
| `DeepLinkIssues.java` | `getParcelableExtra("next_intent")` passed to `startActivity` (intent redirection) | - |
| `Deserialization.java` | `ObjectInputStream.readObject()` on untrusted bytes | - |
| `PathTraversal.java` | `new File(getFilesDir(), intentExtra)` with no canonicalization | - |
| `CryptoSafe.java` | **None - clean control.** AES-256/GCM, fresh `SecureRandom` IV, `KeyGenerator` | - |
| `NetworkSafe.java` | **None - clean control.** HTTPS-only, no trust overrides | - |
| `StorageSafe.java` | **None - clean control.** `EncryptedSharedPreferences` + `AES256_GCM` MasterKey | - |
| `SensitiveLogging.java` | `Log.i` card number + CVV; `Log.e` with card number + throwable | - |
| `UnsafeReflection.java` | `Class.forName` on Intent-controlled name; `DexClassLoader` from external storage | - |
| `StickyBroadcast.java` | `sendStickyBroadcast` carrying email + session token | - |
| `TokenInUrl.java` | API key in URL query parameter | - |
| `NativeLoad.java` | `System.load` from external-storage path (writable location) | - |
| `DebugEndpoints.java` | Hardcoded `DEBUG=true`; `http://staging…` cleartext endpoint; debug token in query string | - |

## Expected findings (approximate rule IDs)

**Status: UNVERIFIED - rule ID expectations.** The rule-engine modules
(`manifest_rules`, `storage_rules`, …) referenced by
`blindspot/rules/registry.py` are not implemented yet, so these IDs follow
the registry's planned `BS-<category><nn>` scheme and are best-effort
guesses of which checks the fixture content should trip. Reconcile this
table once the real rule IDs land; do **not** treat it as a test oracle
until then.

| # | Source | Expected finding | Guess ID | Notes |
|---|---|---|---|---|
| 1 | APK manifest | `debuggable=true` | BS-M01 | high severity |
| 2 | APK manifest | `allowBackup=true` | BS-M02 | sensitive-data exposure |
| 3 | APK manifest | `usesCleartextTraffic=true` | BS-M03 | - |
| 4 | APK manifest | `targetSdkVersion=28` below current baseline | BS-M04 | medium/info |
| 5 | APK manifest | Dangerous permissions (READ_SMS, SEND_SMS, READ_CONTACTS, FINE_LOCATION, CAMERA, RECORD_AUDIO) | BS-M05 | per-permission findings |
| 6 | APK manifest | Exported `MainActivity` with no permission | BS-M06 | needs-review - launcher-style export |
| 7 | APK manifest | Exported `DebugActivity` (debug in name) | BS-M07 | low/info |
| 8 | APK manifest | Exported `SmsReceiver`, no permission, SMS_RECEIVED | BS-M08 | high - SMS broadcast |
| 9 | APK manifest | Exported `TestProvider`, `grantUriPermissions=true`, no read/write permission | BS-M09 | high |
| 10 | APK manifest | Deep link without `autoVerify` | BS-M10 | medium |
| 11 | `strings.xml` | Hardcoded API key (`AIzaSyD-…`) | BS-S04 | - |
| 12 | `private_key.pem` | Embedded private-key material (labeled fake) | BS-S03 | detection should fire; note fixture is synthetic |
| 13 | HardcodedSecrets | Password literal | BS-S01 | high |
| 14 | HardcodedSecrets | AWS `AKIA…` key pattern | BS-S02 | high |
| 15 | InsecureStorage | `MODE_WORLD_READABLE` | BS-S05 | high |
| 16 | InsecureStorage | Password in `Log.d` | BS-S06 | - |
| 17 | InsecureStorage | Token on external storage | BS-S07 | - |
| 18 | InsecureStorage | Password in Intent extra | BS-S08 | low |
| 19 | InsecureStorage | Token copied to clipboard | BS-S09 | low |
| 20 | SensitiveLogging | Card number / CVV in logs | BS-S06 | same log-leak rule |
| 21 | TrustAllCerts | Empty `X509TrustManager` (trust-all) | BS-N03 | critical |
| 22 | TrustAllCerts | `ALLOW_ALL_HOSTNAME_VERIFIER` | BS-N02 | high |
| 23 | TrustAllCerts / DebugEndpoints | `http://` cleartext URLs | BS-N01 | - |
| 24 | TokenInUrl / DebugEndpoints | Secret in URL query parameter | BS-S10/BS-N08 | - |
| 25 | DebugEndpoints | Hardcoded debug endpoint + debug token | BS-P05/BS-S01 | - |
| 26 | WeakCrypto | MD5 for password hashing | BS-C01 | high |
| 27 | WeakCrypto | DES | BS-C02 | high |
| 28 | WeakCrypto | AES/ECB mode | BS-C03 | high |
| 29 | WeakCrypto | Hardcoded `SecretKeySpec` key | BS-C04 | high |
| 30 | WeakCrypto | Hardcoded `IvParameterSpec` IV | BS-C05 | medium |
| 31 | WeakCrypto | `java.util.Random` for security token | BS-C06 | medium |
| 32 | WebViewBugs | `addJavascriptInterface` | BS-W02 | medium |
| 33 | WebViewBugs | `setAllowUniversalAccessFromFileURLs` | BS-W03 | high |
| 34 | WebViewBugs | `onReceivedSslError` → `handler.proceed()` | BS-W05 | high |
| 35 | WebViewBugs | `loadUrl("http://…")` | BS-W04 | - |
| 36 | WebViewBugs | `setJavaScriptEnabled(true)` | BS-W01 | info/low - heuristic, not a vuln alone |
| 37 | SqlInjection | Concatenated `rawQuery` | BS-W06 | high |
| 38 | CommandInjection | Concatenated `Runtime.exec` | BS-W07 | high |
| 39 | DeepLinkIssues | `getParcelableExtra` → `startActivity` (intent redirection) | BS-W09 | high |
| 40 | Deserialization | `ObjectInputStream.readObject` | BS-W10 | high |
| 41 | PathTraversal | Intent-controlled filename in `new File(dir, …)` | BS-W11 | high |
| 42 | AuthBypass | Hardcoded `admin`/`admin` bypass | BS-A01 | high |
| 43 | AuthBypass | Hardcoded test account | BS-A02 | medium |
| 44 | AuthBypass | Bearer token in plaintext prefs | BS-A03/BS-S11 | - |
| 45 | UnsafeReflection | `DexClassLoader` from external storage | BS-P01 | high |
| 46 | UnsafeReflection | `Class.forName` on Intent-controlled name | BS-W12/BS-P02 | medium |
| 47 | StickyBroadcast | PII/token in sticky broadcast | BS-P03 | medium |
| 48 | NativeLoad | `System.load` from writable location | BS-P04 | medium |

## Expected PASS cases (must not fire)

| Case | Must NOT trigger |
|---|---|
| `CryptoSafe.java` | Weak-cipher / ECB / static-key / static-IV / insecure-randomness rules (the `BS-C02…BS-C06` family). AES/GCM + `SecureRandom` + `KeyGenerator` is the clean pattern. |
| `SqlInjection.lookupSafe()` | SQL-injection rule (`BS-W06` family) - parameterized query is the clean control. |
| `NetworkSafe.java` | Cleartext (`BS-N01`) and certificate-validation (`BS-N02`/`BS-N03`) rules - HTTPS-only, no overrides. |
| `StorageSafe.java` | Insecure-storage rules (`BS-S05`/`BS-S07`/`BS-S11` family) - `EncryptedSharedPreferences` is the clean pattern. |

## Known fixture deviations (documented, not defects)

- **AXML string-pool alignment:** androguard 4.1.4 prints
  `WARNING: Size of strings is not aligned by four bytes` for the generated
  manifest (the encoder in `blindspot/analysis/axml.py` does not pad the
  string-pool data to a 4-byte boundary, unlike aapt). androguard still
  validates and parses the APK successfully (`APK file was successfully
  validated!`, correct package/version/permissions/debuggable). Cosmetic only.
- **APK is not installable:** no DEX, no compiled resources (`resources.arsc`),
  dummy `.so`. It is a parse-target for the static pipeline, not a runnable app.
- **No real signatures:** `META-INF/MANIFEST.MF` is dummy text; signature
  verification is not expected to succeed.
