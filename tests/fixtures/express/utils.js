import child_process from 'node:child_process';
export function execute(command) { child_process.exec(command); }
