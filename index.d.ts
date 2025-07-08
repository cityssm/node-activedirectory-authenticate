import { type ClientOptions } from 'ldapts';
export type ActiveDirectoryAuthenticateConfig = ClientOptions & {
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
};
export type ActiveDirectoryAuthenticateResult = {
    success: false;
    error: unknown;
} | {
    success: true;
    sAMAccountName: string;
};
export default class ActiveDirectoryAuthenticate {
    #private;
    constructor(ldapClientOptions: ActiveDirectoryAuthenticateConfig);
    authenticate(userName: string, password: string): Promise<ActiveDirectoryAuthenticateResult>;
}
