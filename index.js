import NodeCache from '@cacheable/node-cache';
import Debug from 'debug';
import { AndFilter, EqualityFilter, InvalidCredentialsError, Client as LdapClient } from 'ldapts';
import { DEBUG_NAMESPACE } from './debug.config.js';
import { adLdapBindErrors } from './errorTypes.js';
import { getUserNamePart } from './utilities.js';
const debug = Debug(`${DEBUG_NAMESPACE}:index`);
export default class ActiveDirectoryAuthenticate {
    #activeDirectoryAuthenticateConfig;
    #clientOptions;
    #userBindDNsCache;
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
    constructor(ldapClientOptions, activeDirectoryAuthenticateConfig) {
        this.#clientOptions = ldapClientOptions;
        this.#activeDirectoryAuthenticateConfig = activeDirectoryAuthenticateConfig;
        if (this.#activeDirectoryAuthenticateConfig.cacheUserBindDNs ?? false) {
            this.#userBindDNsCache = new NodeCache({
                stdTTL: 60, // Cache for 60 seconds
                useClones: false // Use the same object reference for cached items
            });
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
    async authenticate(userName, password) {
        if (this.#clientOptions.url === '') {
            return {
                success: false,
                bindUserDN: '',
                error: new Error('LDAP client URL is not configured.'),
                errorType: 'CONFIGURATION_ERROR'
            };
        }
        /*
         * Skip authentication if an empty username or password is provided.
         */
        if (userName === '' || password === '') {
            return {
                success: false,
                bindUserDN: '',
                errorType: userName === '' ? 'EMPTY_USER_NAME' : 'EMPTY_PASSWORD'
            };
        }
        /*
         * Create a new LDAP client instance with the provided options.
         */
        const client = new LdapClient(this.#clientOptions);
        const sAMAccountName = getUserNamePart(userName);
        let userBindDN = this.#userBindDNsCache?.get(sAMAccountName);
        /*
         * Bind to the LDAP server using the bind user DN and password.
         * This is necessary to perform a search for the user.
         */
        if (userBindDN === undefined) {
            try {
                await client.bind(this.#activeDirectoryAuthenticateConfig.bindUserDN, this.#activeDirectoryAuthenticateConfig.bindUserPassword);
                debug('Successfully bound to LDAP server as %s', this.#activeDirectoryAuthenticateConfig.bindUserDN);
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
                });
                const resultUser = await client.search(this.#activeDirectoryAuthenticateConfig.baseDN, {
                    filter: searchFilter,
                    scope: 'sub'
                });
                if (resultUser.searchEntries.length === 0) {
                    return {
                        success: false,
                        bindUserDN: this.#activeDirectoryAuthenticateConfig.bindUserDN,
                        error: new Error(`User with sAMAccountName "${sAMAccountName}" not found.`),
                        errorType: 'ACCOUNT_NOT_FOUND'
                    };
                }
                userBindDN = resultUser.searchEntries[0].dn;
                if (this.#activeDirectoryAuthenticateConfig.cacheUserBindDNs ?? false) {
                    this.#userBindDNsCache?.set(sAMAccountName, userBindDN);
                }
            }
            catch (error) {
                return {
                    success: false,
                    bindUserDN: this.#activeDirectoryAuthenticateConfig.bindUserDN,
                    error,
                    errorType: 'LDAP_SEARCH_FAILED'
                };
            }
            finally {
                await client.unbind();
            }
        }
        /*
         * Bind to the LDAP server using the user's DN and password to authenticate.
         * If the bind is successful, the user is authenticated.
         * If the bind fails, an error is returned.
         */
        try {
            await client.bind(userBindDN, password);
            return {
                success: true,
                bindUserDN: userBindDN,
                sAMAccountName
            };
        }
        catch (error) {
            let errorType = 'AUTHENTICATION_FAILED';
            if (error instanceof InvalidCredentialsError) {
                for (const [errorMessagePiece, errorTypePiece] of Object.entries(adLdapBindErrors)) {
                    if (error.message.includes(errorMessagePiece)) {
                        errorType = errorTypePiece;
                        break;
                    }
                }
            }
            return {
                success: false,
                bindUserDN: userBindDN,
                error,
                errorType
            };
        }
        finally {
            await client.unbind();
        }
    }
    /**
     * Clears the cache of user bind DNs.
     * This method is used to clear the cached user bind DNs and their associated timeouts.
     * Useful when you want to ensure that the next authentication attempt will not use a cached user bind DN,
     * or if you are exiting your application.
     */
    clearCache() {
        this.#userBindDNsCache?.flushAll();
    }
}
export { activeDirectoryErrors } from './errorTypes.js';
