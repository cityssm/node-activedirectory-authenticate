import assert from 'node:assert'
import { after, describe, it } from 'node:test'

import Debug from 'debug'

import { DEBUG_ENABLE_NAMESPACES } from '../debug.config.js'
import ActiveDirectoryAuthenticate from '../index.js'

import {
  activeDirectoryAuthenticateConfig,
  failureUsers,
  ldapClientOptions,
  successUsers
} from './config.local.js'

Debug.enable(DEBUG_ENABLE_NAMESPACES)

const debug = Debug('activedirectory-authenticate:test')

await describe('activedirectory-authenticate', async () => {
  const authenticator = new ActiveDirectoryAuthenticate(
    ldapClientOptions,
    activeDirectoryAuthenticateConfig
  )

  after(() => {
    authenticator.clearCache()
  })

  for (const [userName, password] of successUsers) {
    await it(`should authenticate user "${userName}"`, async () => {
      const result = await authenticator.authenticate(userName, password)

      debug(`Authentication result for "${userName}":`, result)

      assert.strictEqual(
        result.success,
        true,
        `Authentication for "${userName}" should succeed`
      )
    })
  }

  for (const [userName, password] of failureUsers) {
    await it(`should not authenticate user "${userName}"`, async () => {
      const result = await authenticator.authenticate(userName, password)

      debug(`Authentication result for "${userName}":`, result)

      assert.strictEqual(
        result.success,
        false,
        `Authentication for "${userName}" should fail`
      )
    })
  }
})
