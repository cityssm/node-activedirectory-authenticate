import Debug from 'debug';
import { AndFilter, EqualityFilter, Client as LdapClient } from 'ldapts';
import { DEBUG_NAMESPACE } from './debug.config.js';
import { getUserNamePart } from './utilities.js';
const debug = Debug(`${DEBUG_NAMESPACE}:index`);
export default class ActiveDirectoryAuthenticate {
    #ldapClientOptions;
    constructor(ldapClientOptions) {
        this.#ldapClientOptions = ldapClientOptions;
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
        const client = new LdapClient(this.#ldapClientOptions);
        let userBindDN = '';
        let sAMAccountName = '';
        try {
            await client.bind(this.#ldapClientOptions.bindUserDN, this.#ldapClientOptions.bindUserPassword);
            debug('Successfully bound to LDAP server as %s', this.#ldapClientOptions.bindUserDN);
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
            const resultUser = await client.search(this.#ldapClientOptions.baseDN, {
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
