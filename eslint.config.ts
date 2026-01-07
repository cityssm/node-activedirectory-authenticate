import eslintConfigCityssm, {
  type Config,
  defineConfig
} from 'eslint-config-cityssm'
import { cspellWords } from 'eslint-config-cityssm/exports.js'

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
}) as Config

export default config
