# Active Directory Authenticate for Node

**Just Active Directory authentication and nothing more!**

Based on the work in the deprecated [activedirectory2](https://www.npmjs.com/package/activedirectory2).

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
```

See [ldapts](https://www.npmjs.com/package/ldapts) for the available connection options,
including timeouts and TLS settings.
