# Release policy

The owner requires normal public releases for Android and Windows, never prereleases, unless they explicitly change this instruction. Publish tested builds and activate the corresponding app update feeds; do not stop at a draft or release candidate.

Preserve Android production signing identity and package name for in-place updates. Never publish an unsigned or development APK in the production update feed. Never commit signing keys or credentials.

Existing installed updaters require immutable tagged raw.githubusercontent.com download URLs. Publish and verify the exact tagged binaries, sizes and SHA-256 hashes before updating update.json or windows-update.json. Keep older releases and tags intact.

Document actual validation and limitations; do not claim public endpoint checks prove signed-in functionality or availability on every provider. Do not launch a Windows installer, UAC or WinDivert on the owner's computer without explicit authorization for that test.
