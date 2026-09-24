import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export type Pki = {
  dir: string
  ca: string
  server: { cert: string; key: string }
  client: { cert: string; key: string }
}

function openssl(dir: string, ...args: string[]): void {
  execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' })
}

function issue(dir: string, name: string, eku: string, san: string): void {
  openssl(
    dir,
    'genpkey',
    '-algorithm',
    'EC',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-out',
    `${name}-key.pem`,
  )
  openssl(dir, 'req', '-new', '-key', `${name}-key.pem`, '-out', `${name}.csr`, '-subj', `/CN=${name}`)
  writeFileSync(
    join(dir, `${name}.ext`),
    `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=${eku}\nsubjectAltName=${san}\n`,
  )
  openssl(
    dir,
    'x509',
    '-req',
    '-in',
    `${name}.csr`,
    '-CA',
    'ca.pem',
    '-CAkey',
    'ca-key.pem',
    '-CAcreateserial',
    '-out',
    `${name}.pem`,
    '-days',
    '1',
    '-extfile',
    `${name}.ext`,
  )
}

/** A throwaway CA with a server (localhost) and a dashboard-api client certificate, like the dev PKI. */
export function makePki(): Pki {
  const dir = mkdtempSync(join(tmpdir(), 'dashboard-pki-'))
  openssl(dir, 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', 'ca-key.pem')
  openssl(
    dir,
    'req',
    '-x509',
    '-new',
    '-key',
    'ca-key.pem',
    '-out',
    'ca.pem',
    '-days',
    '1',
    '-subj',
    '/CN=test CA',
    '-addext',
    'basicConstraints=critical,CA:TRUE',
    '-addext',
    'keyUsage=critical,keyCertSign',
  )
  issue(dir, 'server', 'serverAuth', 'DNS:localhost,IP:127.0.0.1')
  issue(dir, 'client', 'clientAuth', 'URI:spiffe://jarvis.local/dashboard-api')
  const read = (f: string) => readFileSync(join(dir, f), 'utf8')
  return {
    dir,
    ca: read('ca.pem'),
    server: { cert: read('server.pem'), key: read('server-key.pem') },
    client: { cert: read('client.pem'), key: read('client-key.pem') },
  }
}
