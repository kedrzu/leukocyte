import { spawn } from 'node:child_process';

import { Option, UsageError } from '@nzyme/cli-core';
import type { CommandClass } from '@nzyme/cli-core/Command.js';
import { Command } from '@nzyme/cli-core/Command.js';
import { EnvVariables } from '@nzyme/ioc/helpers/EnvVariables.js';
import type { SecretsCommandsOptions } from '@nzyme/secrets/commands/SecretsCommandsOptions.js';
import { getSecretDeclarations } from '@nzyme/secrets/commands/utils/getSecretDeclarations.js';
import { mergeStores, readStores } from '@nzyme/secrets/utils/readStores.js';

export const DEFAULT_REPO = 'kedrzu/leukocyte';

/** Params of {@link pushToGithub}. */
export interface PushToGithubParams {
    /** Secret name to value. */
    secrets: ReadonlyMap<string, string>;
    repo: string;
    /** Where messages go: names and exit codes only, never a value. */
    write: (line: string) => void;
    /** The `gh` executable; looked up on `env.PATH` when bare. */
    gh?: string;
    env?: NodeJS.ProcessEnv;
}

/**
 * Runs `gh secret set <NAME> -R <repo>` for each secret, the value written to the child's stdin only. Stops at the
 * first failure and resolves to the exit code for the command.
 */
export async function pushToGithub(params: PushToGithubParams): Promise<number> {
    const { secrets, repo, write, gh = 'gh', env } = params;
    for (const [name, value] of secrets) {
        const { exitCode, error } = await runWithStdin(gh, ['secret', 'set', name, '-R', repo], value, env);
        if (error) {
            write(`Could not start ${gh}: ${error.message}`);
            return 1;
        }

        if (exitCode !== 0) {
            write(`gh failed for ${name} (exit code ${exitCode}); the remaining secrets were not pushed`);
            return 1;
        }

        write(`set ${name}`);
    }

    return 0;
}

/** The child's output is discarded: only its exit code is reported, so nothing it prints can carry a value. */
function runWithStdin(executable: string, args: string[], input: string, env?: NodeJS.ProcessEnv) {
    return new Promise<{ exitCode: number; error?: Error }>(resolve => {
        const child = spawn(executable, args, { stdio: ['pipe', 'ignore', 'ignore'], env });
        child.on('error', error => resolve({ exitCode: 127, error }));
        child.on('close', code => resolve({ exitCode: code ?? 1 }));
        // A child that exits before reading all of stdin closes the pipe; its exit code tells the story.
        child.stdin.on('error', () => undefined);
        child.stdin.end(input);
    });
}

/**
 * Defines `secrets push-github`: pushes every declared secret from the store to the repository's GitHub
 * Actions secrets.
 * @__NO_SIDE_EFFECTS__
 */
export function definePushGithubCommand(options: SecretsCommandsOptions): CommandClass {
    return class PushGithubCommand extends Command {
        static override paths = [['secrets', 'push-github']];
        static override usage = Command.Usage({
            category: 'Secrets',
            description: "Push every declared secret to the repository's GitHub Actions secrets",
            details: `
                Reads the store, then runs \`gh secret set <NAME> -R <repo>\` for each declared secret with the value
                on the child's stdin only — never in an argument. Prints \`set <NAME>\` per secret and nothing else
                about them. Nothing is pushed when any value is missing from the store. Needs \`gh\`, logged in with
                access to the repository's secrets.
            `,
            examples: [['Push to the default repository', 'secrets push-github']],
        });

        repo = Option.String('--repo', DEFAULT_REPO, { description: `The repository, \`${DEFAULT_REPO}\` by default` });

        override async run() {
            const { stores, secrets: definitions } = this.container.resolve(options.provider);
            if (!definitions) {
                throw new UsageError('The provider declares no secrets to push.');
            }

            const names = getSecretDeclarations(definitions, this.container.resolve(EnvVariables)).enabled;
            const merged = mergeStores(await readStores(stores));
            const values = new Map<string, string>();
            const missing: string[] = [];
            for (const name of names) {
                const value = merged.get(name);
                if (value === undefined) {
                    missing.push(name);
                } else {
                    values.set(name, value);
                }
            }

            if (missing.length > 0) {
                this.context.stderr.write(`Not in the store, nothing pushed: ${missing.join(', ')}\n`);
                return 1;
            }

            return await pushToGithub({
                secrets: values,
                repo: this.repo,
                write: line => this.context.stdout.write(`${line}\n`),
            });
        }
    };
}
