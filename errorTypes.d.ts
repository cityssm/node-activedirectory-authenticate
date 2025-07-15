export declare const activeDirectoryErrors: {
    readonly '52e': "LOGON_FAILURE";
    readonly '525': "NO_SUCH_USER";
    readonly '530': "INVALID_LOGIN_HOURS";
    readonly '531': "INVALID_WORKSTATION";
    readonly '532': "PASSWORD_EXPIRED";
    readonly '533': "ACCOUNT_DISABLED";
    readonly '534': "INVALID_LOGIN_TYPE";
    readonly '701': "ACCOUNT_EXPIRED";
    readonly '773': "PASSWORD_MUST_CHANGE";
    readonly '775': "ACCOUNT_LOCKED_OUT";
};
export declare const adLdapBindErrors: Record<` data ${keyof typeof activeDirectoryErrors}, `, (typeof activeDirectoryErrors)[keyof typeof activeDirectoryErrors]>;
export type ActiveDirectoryAuthenticateErrorType = 'ACCOUNT_NOT_FOUND' | 'AUTHENTICATION_FAILED' | 'CONFIGURATION_ERROR' | 'EMPTY_PASSWORD' | 'EMPTY_USER_NAME' | 'LDAP_SEARCH_FAILED' | (typeof activeDirectoryErrors)[keyof typeof activeDirectoryErrors];
