## 0.2.0.260513_alpha (2026-05-17)

* feat: add `clear_totp.py` for maintenance purposes ([db06f9d](https://github.com/cfms-dev/cfms_on_websocket/commit/db06f9d))

### BREAKING CHANGES

* Users' TOTP backup codes will be calculated and stored using the `argon2id` algorithm. This means that previously generated backup codes will become invalid and may throw two exceptions that are not designed to be caught during verification: `VerificationError` and `InvalidHashError`. Consider running `src\maintenance_scripts\clear_totp.py` immediately after the update to clear the two-step verification status for all users, allowing them to reset afterward.
