import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { pushToGithub } from './pushGithub.ts';

const SECRETS = new Map([
    ['APPLE_ID', 'value-one-SECRET-aaa'],
    ['APPLE_PASSWORD', 'value-two-SECRET-bbb\nsecond line'],
]);

/** A `gh` that records each call's argv and stdin as one JSON line, and exits with `$FAKE_GH_EXIT` (default 0). */
const FAKE_GH = `#!/bin/sh
stdin="$(cat)"
bun -e 'console.log(JSON.stringify({ argv: process.argv.slice(1), stdin: process.argv[process.argv.length - 1] }))' -- "$@" "$stdin" >> "$FAKE_GH_LOG"
exit "\${FAKE_GH_EXIT:-0}"
`;

interface Call {
    argv: string[];
    stdin: string;
}

describe('pushToGithub', () => {
    let dir: string;
    let log: string;

    beforeEach(async () => {
        dir = await mkdtemp(join(tmpdir(), 'fake-gh-'));
        log = join(dir, 'calls.jsonl');
        await writeFile(log, '');
        await writeFile(join(dir, 'gh'), FAKE_GH);
        await chmod(join(dir, 'gh'), 0o755);
    });

    afterEach(async () => {
        await rm(dir, { recursive: true, force: true });
    });

    async function calls(): Promise<Call[]> {
        const lines = (await readFile(log, 'utf8')).split('\n').filter(Boolean);
        return lines.map(line => {
            const { argv, stdin } = JSON.parse(line) as { argv: string[]; stdin: string };
            // The stdin travels as the last argument of the recorder, after the real argv.
            return { argv: argv.slice(0, -1), stdin };
        });
    }

    function env(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
        // The fake `gh` comes first on PATH; `bun` stays resolvable for the recorder.
        return {
            ...process.env,
            PATH: `${dir}:${process.env.PATH ?? ''}`,
            FAKE_GH_LOG: log,
            ...extra,
        };
    }

    test('passes each value on stdin only, and prints only names', async () => {
        const output: string[] = [];
        const exitCode = await pushToGithub({
            secrets: SECRETS,
            repo: 'owner/repo',
            write: line => output.push(line),
            env: env(),
        });

        expect(exitCode).toBe(0);
        expect(output).toEqual(['set APPLE_ID', 'set APPLE_PASSWORD']);

        const recorded = await calls();
        expect(recorded.map(call => call.stdin)).toEqual([...SECRETS.values()]);
        expect(recorded.map(call => call.argv)).toEqual([
            ['secret', 'set', 'APPLE_ID', '-R', 'owner/repo'],
            ['secret', 'set', 'APPLE_PASSWORD', '-R', 'owner/repo'],
        ]);

        for (const value of SECRETS.values()) {
            for (const call of recorded) {
                expect(call.argv.join(' ')).not.toContain(value);
            }

            expect(output.join('\n')).not.toContain(value);
        }
    });

    test('stops at a failing gh and reports no value', async () => {
        const output: string[] = [];
        const exitCode = await pushToGithub({
            secrets: SECRETS,
            repo: 'owner/repo',
            write: line => output.push(line),
            env: env({ FAKE_GH_EXIT: '3' }),
        });

        expect(exitCode).toBe(1);
        expect(await calls()).toHaveLength(1);
        expect(output).toEqual(['gh failed for APPLE_ID (exit code 3); the remaining secrets were not pushed']);
    });

    test('reports a missing gh without a value', async () => {
        const output: string[] = [];
        const exitCode = await pushToGithub({
            secrets: SECRETS,
            repo: 'owner/repo',
            write: line => output.push(line),
            gh: join(dir, 'no-such-gh'),
            env: env(),
        });

        expect(exitCode).toBe(1);
        for (const value of SECRETS.values()) {
            expect(output.join('\n')).not.toContain(value);
        }
    });
});
