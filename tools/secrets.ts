/**
 * Every secret leukocyte uses, for `bun secrets …`: the Apple signing and notarization set that
 * `scripts/bundle.sh` reads. They live in Bitwarden under the prefix `LEUKOCYTE_` and are pushed to GitHub
 * with `bun secrets push-github`. How to use them: `docs/secrets.md`.
 */
import { defineSecret } from '@nzyme/secrets/defineSecret.js';

export const APPLE_CERTIFICATE = defineSecret('APPLE_CERTIFICATE', {
    description: 'The Developer ID Application certificate, a base64 .p12',
});

export const APPLE_CERTIFICATE_PASSWORD = defineSecret('APPLE_CERTIFICATE_PASSWORD', {
    description: "The .p12's export password",
});

export const APPLE_SIGNING_IDENTITY = defineSecret('APPLE_SIGNING_IDENTITY', {
    description: 'The signing identity, "Developer ID Application: Name (TEAMID)"',
});

export const APPLE_ID = defineSecret('APPLE_ID', {
    description: "The Apple Account's email, for notarization",
});

export const APPLE_PASSWORD = defineSecret('APPLE_PASSWORD', {
    description: 'An app-specific password of APPLE_ID, for notarization',
});

export const APPLE_TEAM_ID = defineSecret('APPLE_TEAM_ID', {
    description: 'The Apple Developer team ID',
});
