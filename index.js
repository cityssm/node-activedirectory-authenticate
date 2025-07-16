import { NodeCache } from '@cacheable/node-cache';
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
     * @param ldapClientUrlOrOptions - The LDAP URL, or the options for the LDAP client connection.
     * This can be a string in the format 'ldap://example.com' or 'ldaps://example.com',
     * or an object of type LdapClientOptions.
     * If a string is provided, it will be used as the URL for the LDAP connection.
     * If an object is provided, it should contain the necessary options for connecting to the LDAP server.
     * Example: { url: 'ldap://example.com' } or { url: 'ldaps://example.com', timeout: 5000 }
     * @param activeDirectoryAuthenticateConfig - The configuration for Active Directory authentication.
     * This includes the base DN for searching users, the bind user DN, and the bind user password.
     * Example: { baseDN: 'DC=example,DC=com', bindUserDN: 'CN=admin,CN=Users,DC=example,DC=com', bindUserPassword: 'password123' }
     */
    constructor(ldapClientUrlOrOptions, activeDirectoryAuthenticateConfig) {
        this.#clientOptions =
            typeof ldapClientUrlOrOptions === 'string'
                ? { url: ldapClientUrlOrOptions }
                : ldapClientUrlOrOptions;
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
        if (userName === '' || password === '') {
            return {
                success: false,
                bindUserDN: '',
                errorType: userName === '' ? 'EMPTY_USER_NAME' : 'EMPTY_PASSWORD'
            };
        }
        /*
         * Find the user bind DN for the given user name.
         */
        const sAMAccountName = getUserNamePart(userName);
        let userBindDN = this.#userBindDNsCache?.get(sAMAccountName);
        if (userBindDN === undefined) {
            const userSearchResult = await this.#findUserBindDN(sAMAccountName);
            if (!userSearchResult.success) {
                return userSearchResult.result;
            }
            userBindDN = userSearchResult.userBindDN;
            if (this.#activeDirectoryAuthenticateConfig.cacheUserBindDNs ?? false) {
                this.#userBindDNsCache?.set(sAMAccountName, userBindDN);
            }
        }
        /*
         * Try to bind with the user bind DN and password.
         */
        return await this.#tryUserBind(userBindDN, password, sAMAccountName);
    }
    async #findUserBindDN(sAMAccountName) {
        const client = new LdapClient(this.#clientOptions);
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
                    result: {
                        success: false,
                        bindUserDN: this.#activeDirectoryAuthenticateConfig.bindUserDN,
                        error: new Error(`User with sAMAccountName "${sAMAccountName}" not found.`),
                        errorType: 'ACCOUNT_NOT_FOUND'
                    }
                };
            }
            return {
                success: true,
                userBindDN: resultUser.searchEntries[0].dn
            };
        }
        catch (error) {
            return {
                success: false,
                result: {
                    success: false,
                    bindUserDN: this.#activeDirectoryAuthenticateConfig.bindUserDN,
                    error,
                    errorType: 'LDAP_SEARCH_FAILED'
                }
            };
        }
        finally {
            await client.unbind();
        }
    }
    async #tryUserBind(userBindDN, password, sAMAccountName) {
        const client = new LdapClient(this.#clientOptions);
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
