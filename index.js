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
            const error = {
                code: 0x31,
                errno: 'LDAP_INVALID_CREDENTIALS',
                description: 'User name or password is empty'
            };
            return {
                success: false,
                error
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
                const error = {
                    code: 0x31,
                    errno: 'LDAP_INVALID_CREDENTIALS',
                    description: `User not found for user name: ${sAMAccountName}`
                };
                return {
                    success: false,
                    error
                };
            }
            userBindDN = resultUser.searchEntries[0].dn;
        }
        catch (error) {
            return {
                success: false,
                error
            };
        }
        finally {
            await client.unbind();
        }
        try {
            await client.bind(userBindDN, password);
            return {
                success: true,
                sAMAccountName
            };
        }
        catch (error) {
            return {
                success: false,
                error
            };
        }
        finally {
            await client.unbind();
        }
    }
}
