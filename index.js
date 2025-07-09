import Debug from 'debug';
import { AndFilter, EqualityFilter, Client as LdapClient } from 'ldapts';
import { DEBUG_NAMESPACE } from './debug.config.js';
import { getUserNamePart } from './utilities.js';
const debug = Debug(`${DEBUG_NAMESPACE}:index`);
export default class ActiveDirectoryAuthenticate {
    #activeDirectoryAuthenticateConfig;
    #clientOptions;
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
    }
    async authenticate(userName, password) {
        // Skip authentication if an empty username or password is provided.
        if (userName === '' || password === '') {
            return {
                success: false,
                bindUserDN: '',
                errorType: 'EMPTY_USER_NAME_OR_PASSWORD'
            };
        }
        const client = new LdapClient(this.#clientOptions);
        let userBindDN = '';
        let sAMAccountName = '';
        try {
            await client.bind(this.#activeDirectoryAuthenticateConfig.bindUserDN, this.#activeDirectoryAuthenticateConfig.bindUserPassword);
            debug('Successfully bound to LDAP server as %s', this.#activeDirectoryAuthenticateConfig.bindUserDN);
            sAMAccountName = getUserNamePart(userName);
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
                scope: 'sub',
                filter: searchFilter
            });
            if (resultUser.searchEntries.length === 0) {
                return {
                    success: false,
                    bindUserDN: this.#activeDirectoryAuthenticateConfig.bindUserDN,
                    error: new Error(`User with sAMAccountName "${sAMAccountName}" not found.`),
                    errorType: 'USER_NOT_FOUND'
                };
            }
            userBindDN = resultUser.searchEntries[0].dn;
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
        try {
            await client.bind(userBindDN, password);
            return {
                success: true,
                bindUserDN: userBindDN,
                sAMAccountName
            };
        }
        catch (error) {
            return {
                success: false,
                bindUserDN: userBindDN,
                error,
                errorType: 'AUTHENTICATION_FAILED'
            };
        }
        finally {
            await client.unbind();
        }
    }
}
