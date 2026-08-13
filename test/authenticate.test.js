import assert from 'node:assert';
import { after, describe, it } from 'node:test';
import Debug from 'debug';
import { DEBUG_ENABLE_NAMESPACES, DEBUG_NAMESPACE } from '../debug.config.js';
import ActiveDirectoryAuthenticate from '../index.js';
import { activeDirectoryAuthenticateConfig, failureUsers, ldapClientOptions, ldapUrl, successUsers } from './config.local.js';
Debug.enable(DEBUG_ENABLE_NAMESPACES);
const debug = Debug(`${DEBUG_NAMESPACE}:test`);
await describe('activedirectory-authenticate', async () => {
    const authenticator = new ActiveDirectoryAuthenticate(ldapClientOptions, activeDirectoryAuthenticateConfig);
    after(() => {
        authenticator.clearCache();
    });
    for (const [username, password] of successUsers) {
        // eslint-disable-next-line no-await-in-loop
        await it(`should authenticate user "${username}"`, async () => {
            const result = await authenticator.authenticate(username, password);
            debug(`Authentication result for "${username}":`, result);
            assert.strictEqual(result.success, true, `Authentication for "${username}" should succeed`);
        });
    }
    for (const [username, password] of failureUsers) {
        // eslint-disable-next-line no-await-in-loop
        await it(`should not authenticate user "${username}"`, async () => {
            const result = await authenticator.authenticate(username, password);
            debug(`Authentication result for "${username}":`, result);
            assert.strictEqual(result.success, false, `Authentication for "${username}" should fail`);
        });
    }
});
await describe('activedirectory-authenticate:url', async () => {
    await it('should authenticate a user', async () => {
        const authenticator = new ActiveDirectoryAuthenticate(ldapUrl, activeDirectoryAuthenticateConfig);
        const result = await authenticator.authenticate(successUsers[0][0], successUsers[0][1]);
        debug(`Authentication result for "${successUsers[0][0]}":`, result);
        assert.strictEqual(result.success, true, `Authentication should succeed for "${successUsers[0][0]}"`);
    });
});
