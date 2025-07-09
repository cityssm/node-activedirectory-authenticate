import { type ClientOptions as LdapClientOptions } from 'ldapts';
export type ActiveDirectoryAuthenticateErrorType = 'AUTHENTICATION_FAILED' | 'EMPTY_USER_NAME_OR_PASSWORD' | 'LDAP_SEARCH_FAILED' | 'USER_NOT_FOUND';
export interface ActiveDirectoryAuthenticateConfig {
    /**
     * The base distinguished name (DN) for the LDAP search.
     * This is the starting point in the directory tree where the search for users will begin.
     * It should be set to the root of the user container.
     *
     * Example: 'DC=example,DC=com'
     */
    baseDN: string;
    /**
     * The distinguished name (DN) of the user to bind to the LDAP server.
     * This user must have permission to search for other users in the directory.
     * Often a service account or an administrative account.
     *
     * Example: 'CN=administrator,CN=Users,DC=example,DC=com'
     */
    bindUserDN: string;
    /**
     * The password for the bind user.
     * This should be kept secure and not hard-coded in production code.
     * Used to authenticate the bind user before searching for the target user.
     *
     * Example: 'password123'
     */
    bindUserPassword: string;
}
export type ActiveDirectoryAuthenticateResult = {
    bindUserDN: string;
} & ({
    success: false;
    errorType: ActiveDirectoryAuthenticateErrorType;
    error?: unknown;
} | {
    success: true;
    sAMAccountName: string;
});
export default class ActiveDirectoryAuthenticate {
    #private;
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
    constructor(ldapClientOptions: LdapClientOptions, activeDirectoryAuthenticateConfig: ActiveDirectoryAuthenticateConfig);
    authenticate(userName: string, password: string): Promise<ActiveDirectoryAuthenticateResult>;
}
export type { ClientOptions as LdapClientOptions } from 'ldapts';
