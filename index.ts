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

export type ActiveDirectoryAuthenticateErrorType =
  | 'AUTHENTICATION_FAILED'
  | 'EMPTY_USER_NAME_OR_PASSWORD'
  | 'LDAP_SEARCH_FAILED'
  | 'USER_NOT_FOUND'

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

export type ActiveDirectoryAuthenticateResult = { bindUserDN: string } & (
  | {
      success: false

      errorType: ActiveDirectoryAuthenticateErrorType
      error?: unknown
    }
  | {
      success: true

      sAMAccountName: string
    }
)

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
      return {
        success: false,

        bindUserDN: '',
        errorType: 'EMPTY_USER_NAME_OR_PASSWORD'
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
        return {
          success: false,

          bindUserDN: this.#activeDirectoryAuthenticateConfig.bindUserDN,
          error: new Error(
            `User with sAMAccountName "${sAMAccountName}" not found.`
          ),
          errorType: 'USER_NOT_FOUND'
        }
      }

      userBindDN = resultUser.searchEntries[0].dn
    } catch (error) {
      return {
        success: false,

        bindUserDN: this.#activeDirectoryAuthenticateConfig.bindUserDN,
        error,
        errorType: 'LDAP_SEARCH_FAILED'
      }
    } finally {
      await client.unbind()
    }

    try {
      await client.bind(userBindDN, password)

      return {
        success: true,

        bindUserDN: userBindDN,
        sAMAccountName
      }
    } catch (error) {
      return {
        success: false,

        bindUserDN: userBindDN,
        error,
        errorType: 'AUTHENTICATION_FAILED'
      }
    } finally {
      await client.unbind()
    }
  }
}

export type { ClientOptions as LdapClientOptions } from 'ldapts'
