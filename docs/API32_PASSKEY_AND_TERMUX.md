# API32: browser passkeys and Termux root

## Browser FIDO2 authentication

Chrome and Edge reached ChatGPT verification without a passkey/security-key dialog. Google
Play's native flow and Yubico Authenticator could already use or enumerate the USB key.
The fresh Chrome reproduction on 2026-10-29 identified a failure before transport:

```text
02:32:09.099 BoundBrokerSvc: bind com.google.android.gms.fido.fido2.privileged.START
02:32:09.104 PermCheckPreProcessor: API 149 requires missing permission groups: [android.permission-group.STORAGE]
02:32:09.109 GoogleApiAvailability: ConnectionResult=19
02:32:09.109 GoogleApiAvailability: Google Play services is missing a required permission.
```

GMS 26.41.31 lacked `READ_EXTERNAL_STORAGE`. Its installed implementation maps `STORAGE`
to GMS's own permission below API 33. The LiteGApps default-permission declaration existed,
but the runtime permission was denied. The cause of that mismatch was not established.
With owner approval, the only repair was:

```sh
pm grant com.google.android.gms android.permission.READ_EXTERNAL_STORAGE
```

This gives GMS shared-storage read access on this API32 installation. It does not imply
that every Android/FIDO2 version needs that permission. `WRITE_EXTERNAL_STORAGE` was
unnecessary for this tested branch. Rollback restores the previous permission state:

```sh
pm revoke com.google.android.gms android.permission.READ_EXTERNAL_STORAGE
```

Retest displayed GMS UI, granted USB permission to the YubiKey, completed CTAP2 getInfo,
PIN-based verification and GetAssertion, and returned a credential with GMS success.
The maintainer confirmed ChatGPT login. No PIN, credential ID, challenge, assertion,
cookie or account identifier is published. Post-repair Edge login was not tested.

Google documents code 19 as
[SERVICE_MISSING_PERMISSION](https://developers.google.com/android/reference/com/google/android/gms/common/ConnectionResult).
Native Google login alone does not establish browser FIDO2 API readiness.

## Termux and the configured KernelPatch entry

The Play Store Termux `su` wrapper checked for a real executable at `/system/bin/su`.
KernelPatch intercepts the configured root path, and this installation uses `/system/bin/kp`;
the filesystem precheck prevented the request. Termux was already authorized in APatch.
The owner approved changing only its private wrapper. The original was backed up;
the 131-byte replacement retained its owner, mode 0700 and app-data SELinux context:

```sh
#!/data/data/com.termux/files/usr/bin/bash

unset LD_LIBRARY_PATH LD_PRELOAD
export TERMUX_EXEC_OPTOUT=1

exec /system/bin/kp "$@"
```

A harness using Termux's UID returned UID/GID 0 in `u:r:magisk:s0`. It inherited the
harness's SELinux domain, so this does not establish fresh app-domain/terminal-visible
acceptance; final user confirmation remains pending. Restore the original wrapper to
roll back. A Termux package update may replace the patched file.
