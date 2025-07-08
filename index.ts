import Debug from 'debug'
import {
  type ClientOptions as LdapClientOptions,
  AndFilter,
  EqualityFilter,
  Client as LdapClient
} from 'ldapts'

import { DEBUG_NAMESPACE } from './debug.config.js'
import { getUserNamePart } from './utilities.js'

const debug = Debug(`${DEBUG_NAMESPACE}:index`)

export interface ActiveDirectoryAuthenticateConfig {
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
  readonly #activeDirectoryAuthenticateConfig: ActiveDirectoryAuthenticateConfig
  readonly #clientOptions: LdapClientOptions

  /**
   * Creates an instance of ActiveDirectoryAuthenticate.
   * This class is used to authenticate users against an Active Directory server using LDAP.
   * It requires the LDAP client options and the Active Directory configuration for binding.
   * @param ldapClientOptions - The options for the LDAP client connection.
   * This includes the URL of the LDAP server and any other connection options.
   * Example: { url: 'ldap://example.com' }
   * @param activeDirectoryAuthenticateConfig - The configuration for Active Directory authentication.
   * This includes the base DN for searching users, the bind user DN, and the bind user password.
   * Example: { baseDN: 'DC=example,DC=com', bindUserDN: 'CN=admin,CN=Users,DC=example,DC=com', bindUserPassword: 'password123' }
   */
  constructor(
    ldapClientOptions: LdapClientOptions,
    activeDirectoryAuthenticateConfig: ActiveDirectoryAuthenticateConfig
  ) {
    this.#clientOptions = ldapClientOptions
    this.#activeDirectoryAuthenticateConfig = activeDirectoryAuthenticateConfig
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

    const client = new LdapClient(this.#clientOptions)

    let userBindDN = ''
    let sAMAccountName = ''

    try {
      await client.bind(
        this.#activeDirectoryAuthenticateConfig.bindUserDN,
        this.#activeDirectoryAuthenticateConfig.bindUserPassword
      )

      debug(
        'Successfully bound to LDAP server as %s',
        this.#activeDirectoryAuthenticateConfig.bindUserDN
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

      const resultUser = await client.search(
        this.#activeDirectoryAuthenticateConfig.baseDN,
        {
          scope: 'sub',
          filter: searchFilter
        }
      )

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

export type { ClientOptions as LdapClientOptions } from 'ldapts'
