import { bitwarden } from '@nzyme/bitwarden/bitwarden.js';
import { defineService } from '@nzyme/ioc/Service.js';
import { cached } from '@nzyme/secrets/cached.js';
import { secretsProvider } from '@nzyme/secrets/commands/secretsProvider.js';
import { getSecretDefinitions } from '@nzyme/secrets/getSecretDefinitions.js';

import * as secrets from './secrets.ts';

/** The Bitwarden project, shared with the other repos. */
const PROJECT_ID = '41fe22b4-53d3-4302-b97b-b4f601003c79';
/** Keeps this repo's login apart from the other repos' on this machine. */
const KEYCHAIN_SUFFIX = 'leukocyte';
const CACHE_TTL_MS = 8 * 60 * 60 * 1000;

/** The secrets of `secrets.ts` in Bitwarden, one environment: the keys carry the prefix `LEUKOCYTE_`. */
export const LeukocyteSecrets = defineService({
    name: 'LeukocyteSecrets',
    setup: () =>
        secretsProvider({
            secrets: getSecretDefinitions(secrets),
            store: cached(
                bitwarden({ project: PROJECT_ID, prefix: 'LEUKOCYTE_', keychainSuffix: KEYCHAIN_SUFFIX }),
                { ttl: CACHE_TTL_MS },
            ),
        }),
});
