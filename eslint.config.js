import eslintConfigCityssm, { defineConfig } from 'eslint-config-cityssm/eslint.packageConfig.js';
import { cspellWords } from 'eslint-config-cityssm/exports.js';
const config = defineConfig(eslintConfigCityssm, {
    files: ['**/*.ts', '**/*.js'],
    rules: {
        '@cspell/spellchecker': [
            'warn',
            {
                cspell: {
                    words: [...cspellWords, 'activedirectory', 'ldaps']
                }
            }
        ]
    }
});
export default config;
