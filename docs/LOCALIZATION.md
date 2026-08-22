# Web localization

Northstar ships every supported Web-interface translation as a local static JavaScript pack. The
browser never sends interface text to an online translation service.

The default language is English. English, Simplified Chinese, 中華民國語 (Traditional Chinese),
Korean, Japanese, Spanish, French and German are maintained directly in `web/i18n.js`. The other
retained languages are generated into `web/locales.generated.js` with the open-source MADLAD-400
3B-MT model, then checked for completeness, Unicode validity, model-marker leakage and preservation
of dynamic placeholders. The source model is Apache-2.0 licensed:
https://huggingface.co/google/madlad400-3b-mt

When a generated locale is selected, both the sign-in/registration interface and the independent
chat client display a localized warning that the interface is machine-translated and may contain
errors. The warning is hidden for the eight directly maintained locales.

The catalog intentionally excludes historical and low-resource languages for which the available
model data is too sparse to support a useful complete interface. Esperanto and Latin remain because
the model has sufficient data for them. The exact catalog is declared in `web/i18n.js` and is sorted
by its English display name in the picker.

## Regenerating packs

`scripts/generate-locales.mjs` is the offline build tool. It expects a local `llama-completion`
binary and MADLAD-400 GGUF model under the ignored `.translation-tools` directory. It checkpoints
after every completed language, so an interrupted build can resume. Run `scripts/check-locales.mjs`
after generation; partial packs must not be deployed.
