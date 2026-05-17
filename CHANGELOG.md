## 0.2.0.260517_alpha (2026-05-17)

* feat: add `clear_totp.py` for maintenance purposes ([db06f9d](https://github.com/cfms-dev/cfms_on_websocket/commit/db06f9d))

### BREAKING CHANGES

* Users' TOTP backup codes will be calculated and stored using the `argon2id` algorithm. This means that previously generated backup codes will become invalid and may throw two exceptions that are not designed to be caught during verification: `VerificationError` and `InvalidHashError`. Consider running `src\maintenance_scripts\clear_totp.py` immediately after the update to clear the two-step verification status for all users, allowing them to reset afterward.
* The `pepper` parameter has been added to the configuration file to enhance security. Its value is not automatically set after server-side initialization. For security reasons, please remember to manually set it (this will affect the generation and verification behavior of recovery codes, so please ensure you complete the setting before enabling two-step verification).