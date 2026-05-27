import { createGunzip } from 'node:zlib'
import { createWriteStream, existsSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { pipeline } from 'node:stream/promises'
import { Readable } from 'node:stream'
import { DB_PATH } from './local-db.js'
import { scrubSecrets } from './secrets.js'

const RELEASES_API = 'https://api.github.com/repos/catreeo123/vulnscan/releases/tags/db-latest'
const ASSET_NAME = 'db.sqlite.gz'

export async function bootstrapDb(): Promise<boolean> {
  if (process.env.VULNSCAN_NO_BOOTSTRAP) return false

  process.stderr.write('Bootstrapping advisory database from latest release…\n')

  try {
    const assetUrl = await resolveAssetUrl()
    if (!assetUrl) {
      process.stderr.write(`Bootstrap: no ${ASSET_NAME} asset found in latest release — falling back to full sync\n`)
      return false
    }

    const res = await fetch(assetUrl, {
      headers: { Accept: 'application/octet-stream', 'User-Agent': 'vulnscan' },
      redirect: 'follow',
    })
    if (!res.ok || !res.body) {
      process.stderr.write(`Bootstrap: download failed (HTTP ${res.status}) — falling back to full sync\n`)
      return false
    }

    mkdirSync(dirname(DB_PATH), { recursive: true })
    await pipeline(
      Readable.fromWeb(res.body as import('stream/web').ReadableStream),
      createGunzip(),
      createWriteStream(DB_PATH),
    )

    process.stderr.write('Bootstrap complete.\n')
    return true
  } catch (err) {
    process.stderr.write(
      `Bootstrap: download failed (${scrubSecrets((err as Error).message)}) — falling back to full sync\n`,
    )
    return false
  }
}

export async function maybeBootstrap(): Promise<void> {
  if (!existsSync(DB_PATH)) await bootstrapDb()
}

async function resolveAssetUrl(): Promise<string | null> {
  const res = await fetch(RELEASES_API, {
    headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'vulnscan' },
  })
  if (!res.ok) return null
  const release = (await res.json()) as { assets: { name: string; browser_download_url: string }[] }
  return release.assets.find(a => a.name === ASSET_NAME)?.browser_download_url ?? null
}
