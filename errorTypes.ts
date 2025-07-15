export const activeDirectoryErrors = {
  '52e': 'LOGON_FAILURE',
  '525': 'NO_SUCH_USER',
  '530': 'INVALID_LOGIN_HOURS',
  '531': 'INVALID_WORKSTATION',
  '532': 'PASSWORD_EXPIRED',
  '533': 'ACCOUNT_DISABLED',
  '534': 'INVALID_LOGIN_TYPE',
  '701': 'ACCOUNT_EXPIRED',
  '773': 'PASSWORD_MUST_CHANGE',
  '775': 'ACCOUNT_LOCKED_OUT'
} as const

export const adLdapBindErrors: Record<
  ` data ${keyof typeof activeDirectoryErrors}, `,
  (typeof activeDirectoryErrors)[keyof typeof activeDirectoryErrors]
> = {
  ' data 52e, ': activeDirectoryErrors['52e'],
  ' data 525, ': activeDirectoryErrors['525'],
  ' data 530, ': activeDirectoryErrors['530'],
  ' data 531, ': activeDirectoryErrors['531'],
  ' data 532, ': activeDirectoryErrors['532'],
  ' data 533, ': activeDirectoryErrors['533'],
  ' data 534, ': activeDirectoryErrors['534'],
  ' data 701, ': activeDirectoryErrors['701'],
  ' data 773, ': activeDirectoryErrors['773'],
  ' data 775, ': activeDirectoryErrors['775']
}

export type ActiveDirectoryAuthenticateErrorType =
  | 'ACCOUNT_NOT_FOUND'
  | 'AUTHENTICATION_FAILED'
  | 'CONFIGURATION_ERROR'
  | 'EMPTY_PASSWORD'
  | 'EMPTY_USER_NAME'
  | 'LDAP_SEARCH_FAILED'
  | (typeof activeDirectoryErrors)[keyof typeof activeDirectoryErrors]
