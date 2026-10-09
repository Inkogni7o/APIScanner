import { exec } from 'node:child_process';

export function execute(command: string) {
    exec(command);
}
