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
    bindUserPassword: 'p@ssword'
  }
)

const loginResult = await authenticator.authenticate('example\\userName', 'pass123')

if (loginResult.success) {
  // Credentials validated, log the user in!
}
```

See [ldapts](https://www.npmjs.com/package/ldapts) for the available connection options,
including timeouts and TLS settings.
