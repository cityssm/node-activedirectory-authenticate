# Active Directory Authenticate for Node

**Just Active Directory authentication and nothing more!**

[![npm (scoped)](https://img.shields.io/npm/v/@cityssm/activedirectory-authenticate)](https://www.npmjs.com/package/@cityssm/activedirectory-authenticate)
[![DeepSource](https://app.deepsource.com/gh/cityssm/node-activedirectory-authenticate.svg/?label=active+issues&show_trend=true&token=EnG9kg7Sta5TI_shO2yCySdX)](https://app.deepsource.com/gh/cityssm/node-activedirectory-authenticate/)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=cityssm_node-activedirectory-authenticate&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=cityssm_node-activedirectory-authenticate)

Based on the work in the deprecated packages
[activedirectory2](https://www.npmjs.com/package/activedirectory2) and
[ldapjs](https://www.npmjs.com/package/ldapjs).

## Installation

```sh
npm install @cityssm/activedirectory-authenticate
```

## Usage

```javascript
import ActiveDirectoryAuthenticate from '@cityssm/activedirectory-authenticate'

const authenticator = new ActiveDirectoryAuthenticate(
  {
    url: 'ldap://example.com'
  },
  {
    // The base distinguished name (DN) for the LDAP search.
    baseDN: 'DC=example,DC=com',

    // The DN of the user to bind for searching the directory.
    bindUserDN: 'CN=administrator,DC=example,DC=com',
    bindUserPassword: 'p@ssword',

    // Temporarily cache user bind DNs to reduce LDAP lookups on immediate retries,
    // like typoed passwords.
    cacheUserBindDNs: true
  }
)

const loginResult = await authenticator.authenticate(
  'example\\userName',
  'pass123'
)

if (loginResult.success) {
  // Credentials validated, log the user in!
} else {
  console.log(loginResult.errorType)
  // => "ACCOUNT_NOT_FOUND"
}
```

See [ldapts](https://www.npmjs.com/package/ldapts) for the available connection options,
including timeouts and TLS settings.

### Error Types

Active Directory Authenticate provides descriptive error types,
and translates the codes for common Active Directory errors.
See the `errorType` value in the result object.

| Error Type              | Description                                   | Active Directory Code |
| ----------------------- | --------------------------------------------- | --------------------- |
| `EMPTY_USER_NAME`       | Password empty.                               |                       |
| `EMPTY_PASSWORD`        | Password empty.                               |                       |
| `ACCOUNT_NOT_FOUND`     | Unable to find the user via LDAP search.      |                       |
| `LDAP_SEARCH_FAILED`    | Unknown error searching LDAP for the user.    |                       |
| `AUTHENTICATION_FAILED` | Unknown authentication error.                 |                       |
| `NO_SUCH_USER`          | User not found.                               | `525`                 |
| `LOGON_FAILURE`         | Invalid credentials.                          | `52e`                 |
| `INVALID_LOGIN_HOURS`   | User not permitted to logon at current time.  | `530`                 |
| `INVALID_WORKSTATION`   | User not permitted to logon from workstation. | `531`                 |
| `PASSWORD_EXPIRED`      | Password expired.                             | `532`                 |
| `ACCOUNT_DISABLED`      | Account disabled.                             | `533`                 |
| `INVALID_LOGIN_TYPE`    | User not granted the requested logon type.    | `534`                 |
| `ACCOUNT_EXPIRED`       | Account expired.                              | `701`                 |
| `PASSWORD_MUST_CHANGE`  | User must reset password.                     | `773`                 |
| `ACCOUNT_LOCKED_OUT`    | User account locked.                          | `775`                 |
