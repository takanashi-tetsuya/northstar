/* Northstar-owned integration code; the Swagger UI bundle remains Apache-2.0. */
window.addEventListener('DOMContentLoaded', () => {
  const DisableAuthorizationPlugin = () => ({
    components: {
      AuthorizeBtn: () => null,
      AuthorizeOperationBtn: () => null,
    },
  });

  window.ui = SwaggerUIBundle({
    url: '/api/openapi.yaml',
    dom_id: '#swagger-ui',
    deepLinking: true,
    displayRequestDuration: false,
    docExpansion: 'list',
    defaultModelsExpandDepth: -1,
    filter: true,
    persistAuthorization: false,
    supportedSubmitMethods: [],
    tryItOutEnabled: false,
    validatorUrl: null,
    withCredentials: false,
    plugins: [SwaggerUIBundle.plugins.DownloadUrl, DisableAuthorizationPlugin],
    presets: [SwaggerUIBundle.presets.apis],
  });
});
