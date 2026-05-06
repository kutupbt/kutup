import { execFileSync } from 'node:child_process'

const KUTUP_ROOT = '/home/aa/_e/development/kutup'

/**
 * Wipe postgres + seaweedfs to a clean bootstrap state. ~30 s; only call
 * from the top of a spec that needs a fully-fresh stack (e.g. first-login
 * regression). Bypass for specs that just need an authenticated admin.
 *
 * Idempotent: safe to call multiple times.
 *
 * All command args are hardcoded literals; nothing is interpolated from
 * test input, so the use of `bash -c` is safe by construction.
 */
export function wipeStack(): void {
  const script = [
    'docker compose down -v >/dev/null 2>&1',
    'docker run --rm -v /home/aa/_e/development/kutup/data:/d alpine sh -c "rm -rf /d/seaweedfs-master /d/seaweedfs-volume" >/dev/null 2>&1',
    'docker compose up -d >/dev/null 2>&1',
    'sleep 6',
    'docker compose run --rm seaweedfs-init >/dev/null 2>&1',
  ].join(' && ')
  execFileSync('bash', ['-c', script], { cwd: KUTUP_ROOT, stdio: 'inherit' })
}

/** Confirm the bootstrap admin was just created. */
export function expectFreshBootstrap(): void {
  const out = execFileSync(
    'bash',
    ['-c', 'docker compose logs backend 2>&1 | grep bootstrapAdmins | tail -1'],
    { cwd: KUTUP_ROOT, encoding: 'utf-8' },
  )
  if (!out.includes('created admin account admin@kutup.local')) {
    throw new Error(`bootstrap admin not found in backend logs:\n${out}`)
  }
}
