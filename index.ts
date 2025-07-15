import NodeCache from '@cacheable/node-cache'
import Debug from 'debug'
import {
  type ClientOptions as LdapClientOptions,
  AndFilter,
  EqualityFilter,
  InvalidCredentialsError,
  Client as LdapClient
} from 'ldapts'

import { DEBUG_NAMESPACE } from './debug.config.js'
import {
  type ActiveDirectoryAuthenticateErrorType,
  adLdapBindErrors
} from './errorTypes.js'
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

  /**
   * Optional. If true, the user bind DNs will be cached for 60 seconds for failed logons.
   * This can improve performance by avoiding repeated searches for the same user.
   * If false, the user bind DNs will not be cached and will be looked up each time.
   * Default is false.
   */
  cacheUserBindDNs?: boolean
}

export type ActiveDirectoryAuthenticateResult = { bindUserDN: string } & (
  | {
      success: false

      error?: unknown
      errorType: ActiveDirectoryAuthenticateErrorType
    }
  | {
      success: true

      sAMAccountName: string
    }
)

export default class ActiveDirectoryAuthenticate {
  readonly #activeDirectoryAuthenticateConfig: ActiveDirectoryAuthenticateConfig
  readonly #clientOptions: LdapClientOptions

  readonly #userBindDNsCache: NodeCache | undefined

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

    if (this.#activeDirectoryAuthenticateConfig.cacheUserBindDNs ?? false) {
      this.#userBindDNsCache = new NodeCache({
        stdTTL: 60, // Cache for 60 seconds
        useClones: false // Use the same object reference for cached items
      })
    }
  }

  /**
   * Authenticates a user against the Active Directory server.
   * @param userName - The user name to authenticate. Domain names are removed.
   * Can be in the format 'domain\username', 'username', or 'username@domain.com'.
   * @param password - The password for the user to authenticate.
   * @returns A promise that resolves to an object indicating the success or failure of the authentication.
   * If successful, it returns the bind user DN and the sAMAccountName of the authenticated user.
   * If unsuccessful, it returns an error type and message.
   */
  async authenticate(
    userName: string,
    password: string
  ): Promise<ActiveDirectoryAuthenticateResult> {
    if (this.#clientOptions.url === '') {
      return {
        success: false,

        bindUserDN: '',
        error: new Error('LDAP client URL is not configured.'),
        errorType: 'CONFIGURATION_ERROR'
      }
    }

    if (userName === '' || password === '') {
      return {
        success: false,

        bindUserDN: '',
        errorType: userName === '' ? 'EMPTY_USER_NAME' : 'EMPTY_PASSWORD'
      }
    }

    const sAMAccountName = getUserNamePart(userName)

    let userBindDN: string | undefined =
      this.#userBindDNsCache?.get(sAMAccountName)

    if (userBindDN === undefined) {
      const userSearchResult = await this.#findUserBindDN(sAMAccountName)

      if (!userSearchResult.success) {
        return userSearchResult.result
      }

      userBindDN = userSearchResult.userBindDN

      if (this.#activeDirectoryAuthenticateConfig.cacheUserBindDNs ?? false) {
        this.#userBindDNsCache?.set(sAMAccountName, userBindDN)
      }
    }

    return await this.#tryUserBind(userBindDN, password, sAMAccountName)
  }

  async #findUserBindDN(
    sAMAccountName: string
  ): Promise<
    | { result: ActiveDirectoryAuthenticateResult; success: false }
    | { success: true; userBindDN: string }
  > {
    const client = new LdapClient(this.#clientOptions)

    try {
      await client.bind(
        this.#activeDirectoryAuthenticateConfig.bindUserDN,
        this.#activeDirectoryAuthenticateConfig.bindUserPassword
      )

      debug(
        'Successfully bound to LDAP server as %s',
        this.#activeDirectoryAuthenticateConfig.bindUserDN
      )

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
          filter: searchFilter,
          scope: 'sub'
        }
      )

      if (resultUser.searchEntries.length === 0) {
        return {
          success: false,

          result: {
            success: false,

            bindUserDN: this.#activeDirectoryAuthenticateConfig.bindUserDN,
            error: new Error(
              `User with sAMAccountName "${sAMAccountName}" not found.`
            ),
            errorType: 'ACCOUNT_NOT_FOUND'
          }
        }
      }

      return {
        success: true,
        userBindDN: resultUser.searchEntries[0].dn
      }
    } catch (error) {
      return {
        success: false,

        result: {
          success: false,

          bindUserDN: this.#activeDirectoryAuthenticateConfig.bindUserDN,
          error,
          errorType: 'LDAP_SEARCH_FAILED'
        }
      }
    } finally {
      await client.unbind()
    }
  }

  async #tryUserBind(
    userBindDN: string,
    password: string,
    sAMAccountName: string
  ): Promise<ActiveDirectoryAuthenticateResult> {
    const client = new LdapClient(this.#clientOptions)

    try {
      await client.bind(userBindDN, password)

      return {
        success: true,

        bindUserDN: userBindDN,
        sAMAccountName
      }
    } catch (error) {
      let errorType: ActiveDirectoryAuthenticateErrorType =
        'AUTHENTICATION_FAILED'

      if (error instanceof InvalidCredentialsError) {
        for (const [errorMessagePiece, errorTypePiece] of Object.entries(
          adLdapBindErrors
        )) {
          if (error.message.includes(errorMessagePiece)) {
            errorType = errorTypePiece
            break
          }
        }
      }
      return {
        success: false,

        bindUserDN: userBindDN,
        error,
        errorType
      }
    } finally {
      await client.unbind()
    }
  }

  /**
   * Clears the cache of user bind DNs.
   * This method is used to clear the cached user bind DNs and their associated timeouts.
   * Useful when you want to ensure that the next authentication attempt will not use a cached user bind DN,
   * or if you are exiting your application.
   */
  clearCache(): void {
    this.#userBindDNsCache?.flushAll()
  }
}

export {
  type ActiveDirectoryAuthenticateErrorType,
  activeDirectoryErrors
} from './errorTypes.js'

export type { ClientOptions as LdapClientOptions } from 'ldapts'
