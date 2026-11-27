/** The leukocyte developer CLI, `bun secrets …` from the repo root (`docs/secrets.md`). */
import { execute } from '@nzyme/cli-core/execute.js';
import { defineSecretsCommands } from '@nzyme/secrets/commands/defineSecretsCommands.js';

import { LeukocyteSecrets } from './LeukocyteSecrets.ts';
import { definePushGithubCommand } from './pushGithub.ts';

await execute({
    name: 'leukocyte-dev',
    commands: [
        ...defineSecretsCommands({ provider: LeukocyteSecrets }),
        definePushGithubCommand({ provider: LeukocyteSecrets }),
    ],
});
