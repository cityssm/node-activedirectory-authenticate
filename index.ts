import Debug from 'debug'
import {
  type ClientOptions,
  AndFilter,
  EqualityFilter,
  Client as LdapClient
} from 'ldapts'

import { DEBUG_NAMESPACE } from './debug.config.js'
import { getUserNamePart } from './utilities.js'

const debug = Debug(`${DEBUG_NAMESPACE}:index`)

export type ActiveDirectoryAuthenticateConfig = ClientOptions & {
  /**
   * The base distinguished name (DN) for the LDAP search.
   * This is the starting point in the directory tree where the search for users will begin.
   * It should be set to the root of the user container.
   *
   * Example: 'DC=example,DC=com'
   */
  baseDN: string

  /**
   * The distinguished name (DN) of the user to bind to the LDAP server.
   * This user must have permission to search for other users in the directory.
   * Often a service account or an administrative account.
   *
   * Example: 'CN=administrator,CN=Users,DC=example,DC=com'
   */
  bindUserDN: string

  /**
   * The password for the bind user.
   * This should be kept secure and not hard-coded in production code.
   * Used to authenticate the bind user before searching for the target user.
   *
   * Example: 'password123'
   */
  bindUserPassword: string
}

export type ActiveDirectoryAuthenticateResult =
  | {
      success: false

      error: unknown
    }
  | {
      success: true

      sAMAccountName: string
    }

export default class ActiveDirectoryAuthenticate {
  readonly #ldapClientOptions: ActiveDirectoryAuthenticateConfig

  constructor(ldapClientOptions: ActiveDirectoryAuthenticateConfig) {
    this.#ldapClientOptions = ldapClientOptions
  }

  async authenticate(
    userName: string,
    password: string
  ): Promise<ActiveDirectoryAuthenticateResult> {
    // Skip authentication if an empty username or password is provided.
    if (userName === '' || password === '') {
      const error = {
        code: 0x31,
        errno: 'LDAP_INVALID_CREDENTIALS',
        description: 'User name or password is empty'
      }

      return {
        success: false,
        error
      }
    }

    const client = new LdapClient(this.#ldapClientOptions)

    let userBindDN = ''
    let sAMAccountName = ''

    try {
      await client.bind(
        this.#ldapClientOptions.bindUserDN,
        this.#ldapClientOptions.bindUserPassword
      )

      debug(
        'Successfully bound to LDAP server as %s',
        this.#ldapClientOptions.bindUserDN
      )

      sAMAccountName = getUserNamePart(userName)

      const searchFilter = new AndFilter({
        filters: [
          new EqualityFilter({
            attribute: 'sAMAccountName',
            value: sAMAccountName
          }),
          new EqualityFilter({
            attribute: 'objectClass',
            value: 'user'
          })
        ]
      })

      const resultUser = await client.search(this.#ldapClientOptions.baseDN, {
        scope: 'sub',
        filter: searchFilter
      })

      if (resultUser.searchEntries.length === 0) {
        const error = {
          code: 0x31,
          errno: 'LDAP_INVALID_CREDENTIALS',
          description: `User not found for user name: ${sAMAccountName}`
        }
        return {
          success: false,

          error
        }
      }

      userBindDN = resultUser.searchEntries[0].dn
    } catch (error) {
      return {
        success: false,

        error
      }
    } finally {
      await client.unbind()
    }

    try {
      await client.bind(userBindDN, password)

      return {
        success: true,

        sAMAccountName
      }
    } catch (error) {
      return {
        success: false,

        error
      }
    } finally {
      await client.unbind()
    }
  }
}
