import { MACHINE_TEMPLATES, MACHINE_TRANSLATIONS } from './locales.generated.js?v=20260813-3';

const STORAGE_KEY = 'northstar:language';

const RECOMMENDED_CODES = new Set(['en', 'zh-CN', 'zh-TW', 'ko', 'ja', 'es', 'fr', 'de']);
const HUMAN_TRANSLATED_CODES = new Set(['en', 'zh-CN', 'zh-TW', 'ko', 'ja', 'es', 'fr', 'de']);
const SUPPORTED_LANGUAGE_CODES = `
  af sq am ar hy az eu be bn bs bg my ca zh-CN zh-TW hr cs da nl en eo et fil
  fi fr gl ka de el gu ha he hi hu is id ga it ja kn kk km ko ku ky lo la lv lt
  mk ms ml mt mr mn ne no fa ps pl pt pa ro ru sr si sk sl so es sw sv ta te th
  tr uk ur uz vi cy xh yo zu
`.trim().split(/\s+/);

const LANGUAGE_OVERRIDES = new Map([
  ['en', { native: 'English', english: 'English' }],
  ['zh-CN', { native: '简体中文', english: 'Simplified Chinese', aliases: 'Chinese Mandarin 中文 汉语' }],
  ['zh-TW', { native: '中華民國語', english: 'Traditional Chinese', aliases: 'Chinese Mandarin 繁體中文 繁体中文 中华民国语 中文' }],
  ['ko', { native: '한국어', english: 'Korean' }],
  ['ja', { native: '日本語', english: 'Japanese' }],
  ['es', { native: 'Español', english: 'Spanish' }],
  ['fr', { native: 'Français', english: 'French' }],
  ['de', { native: 'Deutsch', english: 'German' }],
  ['eo', { native: 'Esperanto', english: 'Esperanto', aliases: '世界语 世界語 constructed language' }],
  ['la', { native: 'Latina', english: 'Latin', aliases: '拉丁语 拉丁語 classical dead language' }],
  ['fil', { native: 'Filipino', english: 'Filipino', aliases: 'Tagalog' }],
]);

function displayLanguageName(code, locale) {
  try {
    return new Intl.DisplayNames([locale], { type: 'language', languageDisplay: 'standard' }).of(code) || code;
  } catch {
    try {
      return new Intl.DisplayNames(['en'], { type: 'language', languageDisplay: 'standard' }).of(code) || code;
    } catch {
      return code;
    }
  }
}

function buildLanguage(code) {
  const override = LANGUAGE_OVERRIDES.get(code) || {};
  const english = override.english || displayLanguageName(code, 'en');
  const native = override.native || displayLanguageName(code, code);
  return Object.freeze({
    code,
    native,
    english,
    label: `${native} / ${english}`,
    recommended: RECOMMENDED_CODES.has(code),
    searchText: `${code} ${native} ${english} ${override.aliases || ''}`.normalize('NFKD').toLocaleLowerCase('en'),
  });
}

export const LANGUAGES = Object.freeze(
  [...new Set(SUPPORTED_LANGUAGE_CODES)]
    .map(buildLanguage)
    .sort((left, right) => left.english.localeCompare(right.english, 'en', { sensitivity: 'base' })),
);
export const RECOMMENDED_LANGUAGES = Object.freeze(
  LANGUAGES.filter(({ recommended }) => recommended),
);

const CODES = LANGUAGES.map(({ code }) => code);
const LANGUAGE_BY_CODE = new Map(LANGUAGES.map((language) => [language.code, language]));

// Source strings remain in Simplified Chinese in the existing UI. Each row is:
// source, English, Traditional Chinese, Korean, Japanese, Spanish, French, German.
// Missing translations deliberately fall back to English instead of leaking a
// different language into the selected interface.
const ROWS = [
  ['语言', 'Language', '語言', '언어', '言語', 'Idioma', 'Langue', 'Sprache'],
  ['推荐', 'Recommended', '推薦', '추천', 'おすすめ', 'Recomendados', 'Recommandé', 'Empfohlen'],
  ['所有语言', 'All languages', '所有語言', '모든 언어', 'すべての言語', 'Todos los idiomas', 'Toutes les langues', 'Alle Sprachen'],
  ['搜索语言', 'Search languages', '搜尋語言', '언어 검색', '言語を検索', 'Buscar idiomas', 'Rechercher des langues', 'Sprachen suchen'],
  ['清除搜索', 'Clear search', '清除搜尋', '검색 지우기', '検索を消去', 'Borrar búsqueda', 'Effacer la recherche', 'Suche löschen'],
  ['执行搜索', 'Run search', '執行搜尋', '검색 실행', '検索を実行', 'Ejecutar búsqueda', 'Lancer la recherche', 'Suche ausführen'],
  ['没有符合条件的语言', 'No matching languages', '沒有符合條件的語言', '일치하는 언어가 없습니다', '一致する言語がありません', 'No hay idiomas coincidentes', 'Aucune langue correspondante', 'Keine passenden Sprachen'],
  ['机器翻译，可能存在错误', 'Machine translation; errors may be present', '機器翻譯，可能存在錯誤', '기계 번역이므로 오류가 있을 수 있습니다', '機械翻訳のため、誤りが含まれる可能性があります', 'Traducción automática; puede contener errores', 'Traduction automatique ; des erreurs sont possibles', 'Maschinelle Übersetzung; Fehler sind möglich'],
  ['主导航', 'Main navigation', '主導覽', '기본 탐색', 'メインナビゲーション', 'Navegación principal', 'Navigation principale', 'Hauptnavigation'],
  ['概览', 'Overview', '概覽', '개요', '概要', 'Resumen', 'Aperçu', 'Übersicht'],
  ['Web 客户端', 'Web client', '網頁客戶端', '웹 클라이언트', 'Webクライアント', 'Cliente web', 'Client web', 'Webclient'],
  ['管理', 'Administration', '管理', '관리', '管理', 'Administración', 'Administration', 'Verwaltung'],
  ['检查服务中', 'Checking service', '正在檢查服務', '서비스 확인 중', 'サービスを確認中', 'Comprobando el servicio', 'Vérification du service', 'Dienst wird geprüft'],
  ['服务在线', 'Service online', '服務上線', '서비스 온라인', 'サービスはオンラインです', 'Servicio en línea', 'Service en ligne', 'Dienst online'],
  ['服务离线', 'Service offline', '服務離線', '서비스 오프라인', 'サービスはオフラインです', 'Servicio sin conexión', 'Service hors ligne', 'Dienst offline'],
  ['开放 · 标准 · 自托管', 'OPEN · STANDARD · SELF-HOSTED', '開放 · 標準 · 自行託管', '개방형 · 표준 · 자체 호스팅', 'オープン · 標準 · セルフホスト', 'ABIERTO · ESTÁNDAR · AUTOALOJADO', 'OUVERT · STANDARD · AUTO-HÉBERGÉ', 'OFFEN · STANDARD · SELBST GEHOSTET'],
  ['一颗属于你的', 'Your own', '一顆屬於你的', '나만의', 'あなた自身の', 'Tu propia', 'Votre propre', 'Dein eigener'],
  ['通信恒星', 'communication star', '通訊恆星', '커뮤니케이션 스타', 'コミュニケーションの星', 'estrella de comunicación', 'étoile de communication', 'Kommunikationsstern'],
  ['面向千人规模的单机 XMPP 服务。标准客户端可直接连接，网页端支持 OMEMO 2 端到端加密，服务端只保存密文。', 'A single-node XMPP service for up to a thousand people. Standard clients connect directly, while the web client provides OMEMO 2 end-to-end encryption and the server stores ciphertext only.', '面向千人規模的單機 XMPP 服務。標準客戶端可直接連線，網頁端支援 OMEMO 2 端對端加密，伺服器僅儲存密文。', '최대 천 명을 위한 단일 노드 XMPP 서비스입니다. 표준 클라이언트가 직접 연결되며 웹 클라이언트는 OMEMO 2 종단간 암호화를 제공하고 서버에는 암호문만 저장됩니다.', '最大1,000人向けのシングルノードXMPPサービスです。標準クライアントが直接接続でき、WebクライアントはOMEMO 2エンドツーエンド暗号化を提供し、サーバーには暗号文のみを保存します。', 'Servicio XMPP de un solo nodo para hasta mil personas. Los clientes estándar se conectan directamente, mientras el cliente web ofrece cifrado de extremo a extremo OMEMO 2 y el servidor solo guarda texto cifrado.', 'Service XMPP à nœud unique pour un millier de personnes. Les clients standard se connectent directement, tandis que le client web fournit le chiffrement de bout en bout OMEMO 2 et le serveur ne conserve que le texte chiffré.', 'Ein XMPP-Dienst auf einem einzelnen Server für bis zu tausend Personen. Standardclients verbinden sich direkt, der Webclient bietet OMEMO-2-Ende-zu-Ende-Verschlüsselung und der Server speichert nur Chiffretext.'],
  ['打开安全 Web 客户端', 'Open secure web client', '開啟安全網頁客戶端', '보안 웹 클라이언트 열기', '安全なWebクライアントを開く', 'Abrir cliente web seguro', 'Ouvrir le client web sécurisé', 'Sicheren Webclient öffnen'],
  ['查看连接参数', 'View connection settings', '檢視連線參數', '연결 설정 보기', '接続設定を表示', 'Ver parámetros de conexión', 'Voir les paramètres de connexion', 'Verbindungseinstellungen anzeigen'],
  ['核心特性', 'Core features', '核心功能', '핵심 기능', '主な機能', 'Funciones principales', 'Fonctionnalités principales', 'Kernfunktionen'],
  ['标准接入', 'Standards-based access', '標準連線', '표준 기반 연결', '標準準拠の接続', 'Acceso estándar', 'Accès normalisé', 'Standardzugang'],
  ['TCP + STARTTLS 与 RFC 7395 WebSocket，兼容桌面、移动和浏览器客户端。', 'TCP + STARTTLS and RFC 7395 WebSocket support desktop, mobile and browser clients.', 'TCP + STARTTLS 與 RFC 7395 WebSocket，相容桌面、行動與瀏覽器客戶端。', 'TCP + STARTTLS 및 RFC 7395 WebSocket으로 데스크톱, 모바일, 브라우저 클라이언트를 지원합니다.', 'TCP + STARTTLSとRFC 7395 WebSocketにより、デスクトップ、モバイル、ブラウザの各クライアントに対応します。', 'TCP + STARTTLS y WebSocket RFC 7395 para clientes de escritorio, móviles y navegadores.', 'TCP + STARTTLS et WebSocket RFC 7395 pour les clients de bureau, mobiles et navigateurs.', 'TCP + STARTTLS und RFC-7395-WebSocket für Desktop-, Mobil- und Browserclients.'],
  ['端到端加密', 'End-to-end encryption', '端對端加密', '종단간 암호화', 'エンドツーエンド暗号化', 'Cifrado de extremo a extremo', 'Chiffrement de bout en bout', 'Ende-zu-Ende-Verschlüsselung'],
  ['网页端使用 OMEMO 2；身份密钥和会话密钥仅保存在用户选择的可信浏览器中。', 'The web client uses OMEMO 2; identity and session keys stay only in browsers trusted by the user.', '網頁端使用 OMEMO 2；身分金鑰與工作階段金鑰僅保存在使用者選擇的可信瀏覽器中。', '웹 클라이언트는 OMEMO 2를 사용하며 신원 및 세션 키는 사용자가 신뢰한 브라우저에만 보관됩니다.', 'WebクライアントはOMEMO 2を使用し、ID鍵とセッション鍵はユーザーが信頼したブラウザだけに保存されます。', 'El cliente web usa OMEMO 2; las claves de identidad y sesión permanecen únicamente en los navegadores de confianza elegidos por el usuario.', 'Le client web utilise OMEMO 2 ; les clés d’identité et de session restent uniquement dans les navigateurs approuvés par l’utilisateur.', 'Der Webclient verwendet OMEMO 2; Identitäts- und Sitzungsschlüssel bleiben ausschließlich in den vom Benutzer vertrauten Browsern.'],
  ['可观测', 'Observable', '可觀測', '관측 가능', '可観測性', 'Observable', 'Observable', 'Beobachtbar'],
  ['结构化日志、健康检查与 Prometheus 指标，让单机运行状态保持透明。', 'Structured logs, health checks and Prometheus metrics keep single-node operations transparent.', '結構化日誌、健康檢查與 Prometheus 指標，讓單機運作狀態保持透明。', '구조화 로그, 상태 확인 및 Prometheus 메트릭으로 단일 노드 운영을 투명하게 유지합니다.', '構造化ログ、ヘルスチェック、Prometheusメトリクスにより、シングルノードの稼働状況を可視化します。', 'Los registros estructurados, las comprobaciones de salud y las métricas de Prometheus hacen transparente el funcionamiento del nodo.', 'Les journaux structurés, les contrôles d’état et les métriques Prometheus rendent le fonctionnement du nœud transparent.', 'Strukturierte Protokolle, Zustandsprüfungen und Prometheus-Metriken machen den Einzelserverbetrieb transparent.'],
  ['完整浏览器客户端', 'Complete browser client', '完整瀏覽器客戶端', '완전한 브라우저 클라이언트', '完全なブラウザクライアント', 'Cliente de navegador completo', 'Client de navigateur complet', 'Vollständiger Browserclient'],
  ['独立页面提供注册、联系人、在线状态、历史消息、送达状态以及 OMEMO 设备指纹管理。默认优先使用端到端加密。', 'A standalone page provides registration, contacts, presence, history, delivery status and OMEMO device fingerprint management. End-to-end encryption is preferred by default.', '獨立頁面提供註冊、聯絡人、線上狀態、歷史訊息、送達狀態與 OMEMO 裝置指紋管理。預設優先使用端對端加密。', '독립 페이지에서 가입, 연락처, 접속 상태, 기록, 전송 상태 및 OMEMO 장치 지문 관리를 제공합니다. 종단간 암호화가 기본 우선됩니다.', '独立ページで登録、連絡先、プレゼンス、履歴、配信状態、OMEMO端末フィンガープリント管理を提供します。デフォルトでエンドツーエンド暗号化を優先します。', 'Una página independiente ofrece registro, contactos, presencia, historial, estado de entrega y gestión de huellas de dispositivos OMEMO. Se prioriza el cifrado de extremo a extremo.', 'Une page autonome fournit l’inscription, les contacts, la présence, l’historique, l’état de livraison et la gestion des empreintes OMEMO. Le chiffrement de bout en bout est privilégié par défaut.', 'Eine eigenständige Seite bietet Registrierung, Kontakte, Präsenz, Verlauf, Zustellstatus und Verwaltung von OMEMO-Gerätefingerabdrücken. Ende-zu-Ende-Verschlüsselung wird standardmäßig bevorzugt.'],
  ['首次在可信设备登录时会生成本机 OMEMO 身份密钥。请核对联系人的设备指纹；共享或临时电脑不要勾选“可信设备”。', 'The first sign-in on a trusted device creates a local OMEMO identity key. Verify contact fingerprints and do not trust shared or temporary computers.', '首次在可信裝置登入時會產生本機 OMEMO 身分金鑰。請核對聯絡人的裝置指紋；共用或臨時電腦請勿設為可信裝置。', '신뢰할 수 있는 장치에서 처음 로그인하면 로컬 OMEMO 신원 키가 생성됩니다. 연락처 지문을 확인하고 공유 또는 임시 컴퓨터는 신뢰하지 마세요.', '信頼できる端末で初めてサインインすると、ローカルOMEMO ID鍵が生成されます。連絡先のフィンガープリントを確認し、共有・一時利用のPCは信頼しないでください。', 'El primer inicio de sesión en un dispositivo de confianza crea una clave de identidad OMEMO local. Verifica las huellas de tus contactos y no confíes en equipos compartidos o temporales.', 'La première connexion sur un appareil de confiance crée une clé d’identité OMEMO locale. Vérifiez les empreintes de vos contacts et n’approuvez pas les ordinateurs partagés ou temporaires.', 'Bei der ersten Anmeldung auf einem vertrauenswürdigen Gerät wird ein lokaler OMEMO-Identitätsschlüssel erstellt. Prüfe Kontaktfingerabdrücke und vertraue keinen gemeinsam oder vorübergehend genutzten Computern.'],
  ['进入客户端', 'Enter client', '進入客戶端', '클라이언트 열기', 'クライアントを開く', 'Entrar al cliente', 'Accéder au client', 'Client öffnen'],
  ['运行控制台', 'Operations console', '運作主控台', '운영 콘솔', '運用コンソール', 'Consola de operaciones', 'Console d’exploitation', 'Betriebskonsole'],
  ['刷新', 'Refresh', '重新整理', '새로고침', '更新', 'Actualizar', 'Actualiser', 'Aktualisieren'],
  ['管理员登录', 'Administrator sign-in', '管理員登入', '관리자 로그인', '管理者ログイン', 'Inicio de sesión de administrador', 'Connexion administrateur', 'Administrator-Anmeldung'],
  ['用户名', 'Username', '使用者名稱', '사용자 이름', 'ユーザー名', 'Nombre de usuario', 'Nom d’utilisateur', 'Benutzername'],
  ['密码', 'Password', '密碼', '비밀번호', 'パスワード', 'Contraseña', 'Mot de passe', 'Passwort'],
  ['登录控制台', 'Sign in to console', '登入主控台', '콘솔 로그인', 'コンソールにログイン', 'Entrar a la consola', 'Se connecter à la console', 'An der Konsole anmelden'],
  ['退出管理', 'Sign out of administration', '登出管理', '관리자 로그아웃', '管理からログアウト', 'Salir de administración', 'Quitter l’administration', 'Verwaltung abmelden'],
  ['账户', 'Accounts', '帳戶', '계정', 'アカウント', 'Cuentas', 'Comptes', 'Konten'],
  ['权限', 'Role', '權限', '권한', '権限', 'Rol', 'Rôle', 'Rolle'],
  ['状态', 'Status', '狀態', '상태', '状態', 'Estado', 'État', 'Status'],
  ['创建时间', 'Created', '建立時間', '생성일', '作成日時', 'Creado', 'Créé', 'Erstellt'],
  ['操作', 'Actions', '操作', '작업', '操作', 'Acciones', 'Actions', 'Aktionen'],
  ['客户端连接参数', 'Client connection settings', '客戶端連線參數', '클라이언트 연결 설정', 'クライアント接続設定', 'Parámetros de conexión del cliente', 'Paramètres de connexion du client', 'Client-Verbindungseinstellungen'],
  ['JID 域', 'JID domain', 'JID 網域', 'JID 도메인', 'JIDドメイン', 'Dominio JID', 'Domaine JID', 'JID-Domäne'],
  ['当前主机', 'Current host', '目前主機', '현재 호스트', '現在のホスト', 'Host actual', 'Hôte actuel', 'Aktueller Host'],
  ['客户端端口', 'Client port', '客戶端連接埠', '클라이언트 포트', 'クライアントポート', 'Puerto del cliente', 'Port client', 'Client-Port'],
  ['网页端加密', 'Web encryption', '網頁端加密', '웹 암호화', 'Web暗号化', 'Cifrado web', 'Chiffrement web', 'Webverschlüsselung'],

  ['返回 Northstar 首页', 'Return to the Northstar home page', '返回 Northstar 首頁', 'Northstar 홈으로 돌아가기', 'Northstarホームに戻る', 'Volver al inicio de Northstar', 'Retour à l’accueil Northstar', 'Zur Northstar-Startseite'],
  ['消息属于交谈的人。', 'Messages belong to the people in the conversation.', '訊息屬於交談的人。', '메시지는 대화하는 사람들의 것입니다.', 'メッセージは会話する人のものです。', 'Los mensajes pertenecen a quienes conversan.', 'Les messages appartiennent aux personnes qui conversent.', 'Nachrichten gehören den Gesprächsteilnehmern.'],
  ['服务器负责可靠投递，OMEMO 负责让内容只在你的设备上打开。', 'The server handles reliable delivery. OMEMO makes sure content opens only on your devices.', '伺服器負責可靠傳送，OMEMO 確保內容僅在你的裝置上開啟。', '서버는 안정적인 전달을 담당하고 OMEMO는 콘텐츠가 사용자의 장치에서만 열리도록 합니다.', 'サーバーは確実な配信を担い、OMEMOは内容をあなたの端末だけで開けるようにします。', 'El servidor se encarga de la entrega fiable. OMEMO hace que el contenido solo se abra en tus dispositivos.', 'Le serveur assure la livraison fiable. OMEMO veille à ce que le contenu ne s’ouvre que sur vos appareils.', 'Der Server sorgt für zuverlässige Zustellung. OMEMO stellt sicher, dass Inhalte nur auf deinen Geräten geöffnet werden.'],
  ['默认启用端到端加密，不加载广告或远程资源', 'End-to-end encryption is enabled by default. No ads or remote resources are loaded.', '預設啟用端對端加密，不載入廣告或遠端資源', '종단간 암호화가 기본으로 활성화되며 광고나 원격 리소스를 불러오지 않습니다.', 'エンドツーエンド暗号化がデフォルトで有効です。広告や外部リソースは読み込みません。', 'El cifrado de extremo a extremo está activado por defecto. No se cargan anuncios ni recursos remotos.', 'Le chiffrement de bout en bout est activé par défaut. Aucune publicité ni ressource distante n’est chargée.', 'Ende-zu-Ende-Verschlüsselung ist standardmäßig aktiviert. Es werden keine Werbung oder externen Ressourcen geladen.'],
  ['欢迎回来', 'Welcome back', '歡迎回來', '다시 오신 것을 환영합니다', 'おかえりなさい', 'Te damos la bienvenida', 'Bon retour', 'Willkommen zurück'],
  ['登录聊天', 'Sign in to chat', '登入聊天', '채팅 로그인', 'チャットにログイン', 'Iniciar sesión en el chat', 'Se connecter au chat', 'Beim Chat anmelden'],
  ['正在读取服务器配置…', 'Reading server configuration…', '正在讀取伺服器設定…', '서버 설정을 읽는 중…', 'サーバー設定を読み込んでいます…', 'Leyendo la configuración del servidor…', 'Lecture de la configuration du serveur…', 'Serverkonfiguration wird gelesen…'],
  ['账号操作', 'Account actions', '帳戶操作', '계정 작업', 'アカウント操作', 'Acciones de cuenta', 'Actions du compte', 'Kontoaktionen'],
  ['登录', 'Sign in', '登入', '로그인', 'ログイン', 'Iniciar sesión', 'Se connecter', 'Anmelden'],
  ['注册', 'Register', '註冊', '가입', '登録', 'Registrarse', 'S’inscrire', 'Registrieren'],
  ['显示密码', 'Show password', '顯示密碼', '비밀번호 표시', 'パスワードを表示', 'Mostrar contraseña', 'Afficher le mot de passe', 'Passwort anzeigen'],
  ['显示', 'Show', '顯示', '표시', '表示', 'Mostrar', 'Afficher', 'Anzeigen'],
  ['隐藏', 'Hide', '隱藏', '숨기기', '非表示', 'Ocultar', 'Masquer', 'Ausblenden'],
  ['安全登录', 'Secure sign-in', '安全登入', '보안 로그인', '安全にログイン', 'Inicio de sesión seguro', 'Connexion sécurisée', 'Sicher anmelden'],
  ['确认密码', 'Confirm password', '確認密碼', '비밀번호 확인', 'パスワード確認', 'Confirmar contraseña', 'Confirmer le mot de passe', 'Passwort bestätigen'],
  ['至少 10 个字符。私钥只会保存在当前浏览器中。', 'At least 10 characters. Private keys stay only in this browser.', '至少 10 個字元。私密金鑰只會保存在目前瀏覽器中。', '10자 이상이어야 합니다. 개인 키는 이 브라우저에만 보관됩니다.', '10文字以上。秘密鍵はこのブラウザだけに保存されます。', 'Al menos 10 caracteres. Las claves privadas permanecen solo en este navegador.', 'Au moins 10 caractères. Les clés privées restent uniquement dans ce navigateur.', 'Mindestens 10 Zeichen. Private Schlüssel bleiben ausschließlich in diesem Browser.'],
  ['创建账号', 'Create account', '建立帳戶', '계정 만들기', 'アカウントを作成', 'Crear cuenta', 'Créer un compte', 'Konto erstellen'],
  ['此客户端需要启用 JavaScript。', 'This client requires JavaScript.', '此客戶端需要啟用 JavaScript。', '이 클라이언트에는 JavaScript가 필요합니다.', 'このクライアントにはJavaScriptが必要です。', 'Este cliente necesita JavaScript.', 'Ce client nécessite JavaScript.', 'Dieser Client benötigt JavaScript.'],
  ['打开设置', 'Open settings', '開啟設定', '설정 열기', '設定を開く', 'Abrir ajustes', 'Ouvrir les paramètres', 'Einstellungen öffnen'],
  ['设置', 'Settings', '設定', '설정', '設定', 'Ajustes', 'Paramètres', 'Einstellungen'],
  ['未连接', 'Not connected', '未連線', '연결되지 않음', '未接続', 'Sin conexión', 'Non connecté', 'Nicht verbunden'],
  ['搜索联系人', 'Search contacts', '搜尋聯絡人', '연락처 검색', '連絡先を検索', 'Buscar contactos', 'Rechercher des contacts', 'Kontakte suchen'],
  ['添加联系人', 'Add contact', '新增聯絡人', '연락처 추가', '連絡先を追加', 'Añadir contacto', 'Ajouter un contact', 'Kontakt hinzufügen'],
  ['会话列表', 'Conversation list', '對話清單', '대화 목록', '会話一覧', 'Lista de conversaciones', 'Liste des conversations', 'Unterhaltungsliste'],
  ['＋ 发起会话', '＋ New conversation', '＋ 發起對話', '＋ 새 대화', '＋ 新しい会話', '＋ Nueva conversación', '＋ Nouvelle conversation', '＋ Neue Unterhaltung'],
  ['# 创建或加入群聊', '# Create or join a group', '# 建立或加入群聊', '# 그룹 만들기 또는 참여', '# グループを作成または参加', '# Crear o unirse a un grupo', '# Créer ou rejoindre un groupe', '# Gruppe erstellen oder beitreten'],
  ['选择一个联系人开始交谈', 'Choose a contact to start a conversation', '選擇一位聯絡人開始交談', '대화를 시작할 연락처를 선택하세요', '連絡先を選んで会話を始めましょう', 'Elige un contacto para iniciar una conversación', 'Choisissez un contact pour commencer une conversation', 'Wähle einen Kontakt, um eine Unterhaltung zu beginnen'],
  ['端到端加密会话会在发送前检查对方设备，并把密钥材料留在你的浏览器中。', 'End-to-end encrypted conversations check recipient devices before sending and keep key material in your browser.', '端對端加密對話會在傳送前檢查對方裝置，並將金鑰資料保留在你的瀏覽器中。', '종단간 암호화 대화는 전송 전에 상대 장치를 확인하고 키 자료를 브라우저에 보관합니다.', 'エンドツーエンド暗号化された会話は送信前に相手の端末を確認し、鍵情報をブラウザ内に保持します。', 'Las conversaciones cifradas de extremo a extremo comprueban los dispositivos del destinatario antes de enviar y conservan las claves en tu navegador.', 'Les conversations chiffrées de bout en bout vérifient les appareils du destinataire avant l’envoi et conservent les clés dans votre navigateur.', 'Ende-zu-Ende-verschlüsselte Unterhaltungen prüfen Empfängergeräte vor dem Senden und behalten Schlüsselmaterial im Browser.'],
  ['发起新会话', 'Start a new conversation', '開始新對話', '새 대화 시작', '新しい会話を開始', 'Iniciar una nueva conversación', 'Démarrer une nouvelle conversation', 'Neue Unterhaltung beginnen'],
  ['返回联系人', 'Back to contacts', '返回聯絡人', '연락처로 돌아가기', '連絡先に戻る', 'Volver a contactos', 'Retour aux contacts', 'Zurück zu Kontakten'],
  ['离线', 'Offline', '離線', '오프라인', 'オフライン', 'Sin conexión', 'Hors ligne', 'Offline'],
  ['检查加密', 'Check encryption', '檢查加密', '암호화 확인', '暗号化を確認', 'Comprobar cifrado', 'Vérifier le chiffrement', 'Verschlüsselung prüfen'],
  ['联系人菜单', 'Contact menu', '聯絡人選單', '연락처 메뉴', '連絡先メニュー', 'Menú del contacto', 'Menu du contact', 'Kontaktmenü'],
  ['正在检查 OMEMO 设备', 'Checking OMEMO devices', '正在檢查 OMEMO 裝置', 'OMEMO 장치 확인 중', 'OMEMO端末を確認中', 'Comprobando dispositivos OMEMO', 'Vérification des appareils OMEMO', 'OMEMO-Geräte werden geprüft'],
  ['发送前会验证对方的公开密钥。', 'Recipient public keys are verified before sending.', '傳送前會驗證對方的公開金鑰。', '전송 전에 상대방의 공개 키를 확인합니다.', '送信前に相手の公開鍵を確認します。', 'Las claves públicas del destinatario se verifican antes de enviar.', 'Les clés publiques du destinataire sont vérifiées avant l’envoi.', 'Öffentliche Schlüssel des Empfängers werden vor dem Senden geprüft.'],
  ['关闭提示', 'Dismiss notice', '關閉提示', '알림 닫기', '通知を閉じる', 'Cerrar aviso', 'Fermer l’avis', 'Hinweis schließen'],
  ['查看更早的加密消息', 'View earlier encrypted messages', '檢視較早的加密訊息', '이전 암호화 메시지 보기', '以前の暗号化メッセージを表示', 'Ver mensajes cifrados anteriores', 'Voir les messages chiffrés précédents', 'Frühere verschlüsselte Nachrichten anzeigen'],
  ['输入消息', 'Write a message', '輸入訊息', '메시지 입력', 'メッセージを入力', 'Escribe un mensaje', 'Écrire un message', 'Nachricht schreiben'],
  ['消息', 'Message', '訊息', '메시지', 'メッセージ', 'Mensaje', 'Message', 'Nachricht'],
  ['发送加密文件', 'Send encrypted file', '傳送加密檔案', '암호화 파일 보내기', '暗号化ファイルを送信', 'Enviar archivo cifrado', 'Envoyer un fichier chiffré', 'Verschlüsselte Datei senden'],
  ['＋ 文件', '＋ File', '＋ 檔案', '＋ 파일', '＋ ファイル', '＋ Archivo', '＋ Fichier', '＋ Datei'],
  ['OMEMO 加密', 'OMEMO encrypted', 'OMEMO 加密', 'OMEMO 암호화', 'OMEMO暗号化', 'Cifrado OMEMO', 'Chiffré avec OMEMO', 'OMEMO-verschlüsselt'],
  ['发送消息', 'Send message', '傳送訊息', '메시지 보내기', 'メッセージを送信', 'Enviar mensaje', 'Envoyer le message', 'Nachricht senden'],
  ['发送', 'Send', '傳送', '보내기', '送信', 'Enviar', 'Envoyer', 'Senden'],
  ['关闭', 'Close', '關閉', '닫기', '閉じる', 'Cerrar', 'Fermer', 'Schließen'],
  ['取消', 'Cancel', '取消', '취소', 'キャンセル', 'Cancelar', 'Annuler', 'Abbrechen'],
  ['XMPP 地址', 'XMPP address', 'XMPP 位址', 'XMPP 주소', 'XMPPアドレス', 'Dirección XMPP', 'Adresse XMPP', 'XMPP-Adresse'],
  ['用户名@服务器', 'username@server', '使用者名稱@伺服器', '사용자이름@서버', 'ユーザー名@サーバー', 'usuario@servidor', 'utilisateur@serveur', 'benutzername@server'],
  ['备注名（可选）', 'Display name (optional)', '備註名稱（選填）', '표시 이름(선택 사항)', '表示名（任意）', 'Nombre visible (opcional)', 'Nom affiché (facultatif)', 'Anzeigename (optional)'],
  ['对方的名字', 'Contact name', '對方的名稱', '연락처 이름', '連絡先の名前', 'Nombre del contacto', 'Nom du contact', 'Name des Kontakts'],
  ['添加后会向对方发送联系人请求。', 'A contact request will be sent after adding this address.', '新增後會向對方傳送聯絡人請求。', '추가하면 연락처 요청이 전송됩니다.', '追加すると連絡先リクエストが送信されます。', 'Al añadir esta dirección se enviará una solicitud de contacto.', 'Une demande de contact sera envoyée après l’ajout de cette adresse.', 'Nach dem Hinzufügen wird eine Kontaktanfrage gesendet.'],
  ['发送请求', 'Send request', '傳送請求', '요청 보내기', 'リクエストを送信', 'Enviar solicitud', 'Envoyer la demande', 'Anfrage senden'],
  ['联系人操作', 'Contact actions', '聯絡人操作', '연락처 작업', '連絡先の操作', 'Acciones del contacto', 'Actions du contact', 'Kontaktaktionen'],
  ['屏蔽联系人', 'Block contact', '封鎖聯絡人', '연락처 차단', '連絡先をブロック', 'Bloquear contacto', 'Bloquer le contact', 'Kontakt blockieren'],
  ['解除屏蔽', 'Unblock contact', '解除封鎖', '차단 해제', 'ブロックを解除', 'Desbloquear contacto', 'Débloquer le contact', 'Kontakt entsperren'],
  ['从联系人列表移除', 'Remove from contacts', '從聯絡人清單移除', '연락처에서 삭제', '連絡先から削除', 'Eliminar de contactos', 'Retirer des contacts', 'Aus Kontakten entfernen'],
  ['创建或加入群聊', 'Create or join a group', '建立或加入群聊', '그룹 만들기 또는 참여', 'グループを作成または参加', 'Crear o unirse a un grupo', 'Créer ou rejoindre un groupe', 'Gruppe erstellen oder beitreten'],
  ['房间名称', 'Room name', '房間名稱', '방 이름', 'ルーム名', 'Nombre de la sala', 'Nom du salon', 'Raumname'],
  ['例如：team', 'For example: team', '例如：team', '예: team', '例: team', 'Por ejemplo: team', 'Par exemple : team', 'Zum Beispiel: team'],
  ['显示名称（可选）', 'Display name (optional)', '顯示名稱（選填）', '표시 이름(선택 사항)', '表示名（任意）', 'Nombre visible (opcional)', 'Nom affiché (facultatif)', 'Anzeigename (optional)'],
  ['例如：项目讨论', 'For example: Project discussion', '例如：專案討論', '예: 프로젝트 토론', '例: プロジェクトの相談', 'Por ejemplo: Debate del proyecto', 'Par exemple : Discussion du projet', 'Zum Beispiel: Projektdiskussion'],
  ['你的群昵称', 'Your group nickname', '你的群組暱稱', '그룹 닉네임', 'グループでのニックネーム', 'Tu apodo en el grupo', 'Votre pseudonyme dans le groupe', 'Dein Gruppenname'],
  ['房间地址为', 'The room address is', '房間位址為', '방 주소:', 'ルームアドレス:', 'La dirección de la sala es', 'L’adresse du salon est', 'Die Raumadresse ist'],
  ['。新房间由创建者管理；群消息使用 OMEMO 分别加密给在线成员的设备。', '. New rooms are managed by their creator; group messages are encrypted with OMEMO for each online member device.', '。新房間由建立者管理；群組訊息使用 OMEMO 分別加密給線上成員的裝置。', '. 새 방은 생성자가 관리하며 그룹 메시지는 각 온라인 구성원의 장치에 OMEMO로 암호화됩니다.', '。新しいルームは作成者が管理し、グループメッセージはオンラインメンバーの各端末向けにOMEMOで暗号化されます。', '. Las salas nuevas son administradas por su creador; los mensajes de grupo se cifran con OMEMO para cada dispositivo conectado.', '. Les nouveaux salons sont gérés par leur créateur ; les messages de groupe sont chiffrés avec OMEMO pour chaque appareil connecté.', '. Neue Räume werden vom Ersteller verwaltet; Gruppennachrichten werden mit OMEMO für jedes Online-Gerät verschlüsselt.'],
  ['进入群聊', 'Enter group', '進入群聊', '그룹 입장', 'グループに入る', 'Entrar al grupo', 'Entrer dans le groupe', 'Gruppe betreten'],
  ['群聊成员', 'Group members', '群聊成員', '그룹 구성원', 'グループメンバー', 'Miembros del grupo', 'Membres du groupe', 'Gruppenmitglieder'],
  ['退出群聊', 'Leave group', '退出群聊', '그룹 나가기', 'グループを退出', 'Salir del grupo', 'Quitter le groupe', 'Gruppe verlassen'],
  ['设备与指纹', 'Devices and fingerprints', '裝置與指紋', '장치 및 지문', '端末とフィンガープリント', 'Dispositivos y huellas', 'Appareils et empreintes', 'Geräte und Fingerabdrücke'],
  ['通过另一条可信渠道比对指纹。首次看到的密钥采用 TOFU（首次使用即信任）；密钥变化时客户端会停止发送。', 'Compare fingerprints through another trusted channel. New keys use TOFU (trust on first use); the client stops sending when a key changes.', '請透過另一個可信管道比對指紋。首次看到的金鑰採用 TOFU（首次使用即信任）；金鑰變更時客戶端會停止傳送。', '다른 신뢰할 수 있는 채널에서 지문을 비교하세요. 새 키는 TOFU(최초 사용 시 신뢰)를 사용하며 키가 변경되면 클라이언트가 전송을 중지합니다.', '別の信頼できる経路でフィンガープリントを照合してください。新しい鍵はTOFU（初回利用時に信頼）を使用し、鍵が変更されるとクライアントは送信を停止します。', 'Compara las huellas por otro canal de confianza. Las claves nuevas usan TOFU (confianza en el primer uso); el cliente deja de enviar si cambia una clave.', 'Comparez les empreintes via un autre canal fiable. Les nouvelles clés utilisent TOFU (confiance à la première utilisation) ; le client cesse d’envoyer si une clé change.', 'Vergleiche Fingerabdrücke über einen anderen vertrauenswürdigen Kanal. Neue Schlüssel verwenden TOFU; bei einer Schlüsseländerung stoppt der Client den Versand.'],
  ['重新检查', 'Check again', '重新檢查', '다시 확인', '再確認', 'Comprobar de nuevo', 'Vérifier à nouveau', 'Erneut prüfen'],
  ['本机设置', 'Local settings', '本機設定', '로컬 설정', 'ローカル設定', 'Ajustes locales', 'Paramètres locaux', 'Lokale Einstellungen'],
  ['加密设备', 'Encryption device', '加密裝置', '암호화 장치', '暗号化端末', 'Dispositivo de cifrado', 'Appareil de chiffrement', 'Verschlüsselungsgerät'],
  ['本机设备 ID', 'Local device ID', '本機裝置 ID', '로컬 장치 ID', 'ローカル端末ID', 'ID del dispositivo local', 'ID de l’appareil local', 'Lokale Geräte-ID'],
  ['本机指纹', 'Local fingerprint', '本機指紋', '로컬 지문', 'ローカルフィンガープリント', 'Huella local', 'Empreinte locale', 'Lokaler Fingerabdruck'],
  ['头像', 'Avatar', '頭像', '아바타', 'アバター', 'Avatar', 'Avatar', 'Avatar'],
  ['发布标准 XMPP 头像与 vCard 照片，其他兼容客户端也可以读取。', 'Publish a standard XMPP avatar and vCard photo that other compatible clients can read.', '發佈標準 XMPP 頭像與 vCard 相片，其他相容客戶端也可以讀取。', '다른 호환 클라이언트에서도 읽을 수 있는 표준 XMPP 아바타와 vCard 사진을 게시합니다.', '他の互換クライアントでも読み取れる標準XMPPアバターとvCard写真を公開します。', 'Publica un avatar XMPP estándar y una foto vCard que otros clientes compatibles puedan leer.', 'Publiez un avatar XMPP standard et une photo vCard lisibles par les autres clients compatibles.', 'Veröffentliche einen standardmäßigen XMPP-Avatar und ein vCard-Foto, die andere kompatible Clients lesen können.'],
  ['选择头像', 'Choose avatar', '選擇頭像', '아바타 선택', 'アバターを選択', 'Elegir avatar', 'Choisir un avatar', 'Avatar auswählen'],
  ['可选择最高 50 MiB 的常见图片。原图只在当前浏览器中读取，裁切、旋转、转码并压缩到 256 KiB 以下后才会发布为标准 XMPP 头像与 vCard 照片。', 'Choose a common image up to 50 MiB. The original is read only in this browser, then cropped, rotated, converted and compressed below 256 KiB before it is published as a standard XMPP avatar and vCard photo.', '可選擇最高 50 MiB 的常見圖片。原圖只會在目前瀏覽器中讀取，裁切、旋轉、轉碼並壓縮至 256 KiB 以下後，才會發佈為標準 XMPP 頭像與 vCard 相片。', '최대 50 MiB의 일반 이미지를 선택할 수 있습니다. 원본은 이 브라우저에서만 읽고 자르기, 회전, 변환 및 256 KiB 미만 압축 후 표준 XMPP 아바타와 vCard 사진으로 게시됩니다.', '最大50 MiBの一般的な画像を選択できます。元画像はこのブラウザ内だけで読み取り、切り抜き・回転・変換・256 KiB未満への圧縮後に標準XMPPアバターとvCard写真として公開します。', 'Elige una imagen común de hasta 50 MiB. El original se lee solo en este navegador y se recorta, gira, convierte y comprime por debajo de 256 KiB antes de publicarse como avatar XMPP y foto vCard estándar.', 'Choisissez une image courante de 50 Mio maximum. L’original est lu uniquement dans ce navigateur, puis recadré, pivoté, converti et compressé sous 256 Kio avant publication comme avatar XMPP et photo vCard standard.', 'Wähle ein gängiges Bild bis 50 MiB. Das Original wird nur in diesem Browser gelesen, zugeschnitten, gedreht, konvertiert und auf unter 256 KiB komprimiert, bevor es als Standard-XMPP-Avatar und vCard-Foto veröffentlicht wird.'],
  ['选择并裁切头像', 'Choose and crop avatar', '選擇並裁切頭像', '아바타 선택 및 자르기', 'アバターを選択して切り抜く', 'Elegir y recortar avatar', 'Choisir et recadrer l’avatar', 'Avatar auswählen und zuschneiden'],
  ['裁切头像', 'Crop avatar', '裁切頭像', '아바타 자르기', 'アバターを切り抜く', 'Recortar avatar', 'Recadrer l’avatar', 'Avatar zuschneiden'],
  ['拖动图片调整位置，使用滑块或鼠标滚轮缩放。圆形线框显示头像在聊天中的可见范围。', 'Drag the image to reposition it. Use the slider or mouse wheel to zoom. The circular outline shows the area visible in chat.', '拖曳圖片調整位置，使用滑桿或滑鼠滾輪縮放。圓形線框會顯示頭像在聊天中的可見範圍。', '이미지를 드래그해 위치를 조정하고 슬라이더나 마우스 휠로 확대하세요. 원형 윤곽선은 채팅에서 보이는 범위를 나타냅니다.', '画像をドラッグして位置を調整し、スライダーまたはマウスホイールで拡大縮小します。円形の枠はチャットで表示される範囲です。', 'Arrastra la imagen para colocarla. Usa el control o la rueda del ratón para ampliar. El contorno circular muestra el área visible en el chat.', 'Faites glisser l’image pour la repositionner. Utilisez le curseur ou la molette pour zoomer. Le cercle indique la zone visible dans la messagerie.', 'Ziehe das Bild zum Positionieren. Zoome mit dem Regler oder Mausrad. Der Kreis zeigt den im Chat sichtbaren Bereich.'],
  ['头像裁切预览', 'Avatar crop preview', '頭像裁切預覽', '아바타 자르기 미리보기', 'アバター切り抜きプレビュー', 'Vista previa del recorte del avatar', 'Aperçu du recadrage de l’avatar', 'Vorschau des Avatar-Zuschnitts'],
  ['缩放', 'Zoom', '縮放', '확대/축소', 'ズーム', 'Zoom', 'Zoom', 'Zoom'],
  ['向左旋转', 'Rotate left', '向左旋轉', '왼쪽으로 회전', '左に回転', 'Girar a la izquierda', 'Pivoter à gauche', 'Nach links drehen'],
  ['向右旋转', 'Rotate right', '向右旋轉', '오른쪽으로 회전', '右に回転', 'Girar a la derecha', 'Pivoter à droite', 'Nach rechts drehen'],
  ['重置', 'Reset', '重設', '재설정', 'リセット', 'Restablecer', 'Réinitialiser', 'Zurücksetzen'],
  ['裁切并发布', 'Crop and publish', '裁切並發佈', '자르고 게시', '切り抜いて公開', 'Recortar y publicar', 'Recadrer et publier', 'Zuschneiden und veröffentlichen'],
  ['请选择不超过 50 MiB 的图片文件', 'Choose an image file no larger than 50 MiB', '請選擇不超過 50 MiB 的圖片檔案', '50 MiB 이하의 이미지 파일을 선택하세요', '50 MiB以下の画像ファイルを選択してください', 'Elige un archivo de imagen de no más de 50 MiB', 'Choisissez un fichier image de 50 Mio maximum', 'Wähle eine Bilddatei mit höchstens 50 MiB'],
  ['正在读取图片…', 'Reading image…', '正在讀取圖片…', '이미지 읽는 중…', '画像を読み込み中…', 'Leyendo imagen…', 'Lecture de l’image…', 'Bild wird gelesen…'],
  ['将输出为标准 JPEG，且小于 256 KiB', 'Output will be standard JPEG below 256 KiB', '將輸出為標準 JPEG，且小於 256 KiB', '256 KiB 미만의 표준 JPEG로 출력됩니다', '256 KiB未満の標準JPEGとして出力します', 'La salida será un JPEG estándar de menos de 256 KiB', 'La sortie sera un JPEG standard de moins de 256 Kio', 'Ausgabe als Standard-JPEG unter 256 KiB'],
  ['正在压缩…', 'Compressing…', '正在壓縮…', '압축 중…', '圧縮中…', 'Comprimiendo…', 'Compression…', 'Wird komprimiert…'],
  ['头像已在本地裁切、压缩并发布', 'Avatar cropped and compressed locally, then published', '頭像已在本機裁切、壓縮並發佈', '아바타를 로컬에서 자르고 압축한 후 게시했습니다', 'アバターをローカルで切り抜き・圧縮して公開しました', 'Avatar recortado y comprimido localmente, y publicado', 'Avatar recadré et compressé localement, puis publié', 'Avatar lokal zugeschnitten, komprimiert und veröffentlicht'],
  ['浏览器无法生成处理后的头像', 'The browser could not generate the processed avatar'],
  ['当前浏览器无法读取这种图片格式', 'This browser cannot read this image format'],
  ['图片像素尺寸过大，无法安全处理', 'The image dimensions are too large to process safely'],
  ['请先选择头像图片', 'Choose an avatar image first'],
  ['无法将头像压缩到 256 KiB 以下', 'The avatar could not be compressed below 256 KiB'],
  ['会话', 'Session', '工作階段', '세션', 'セッション', 'Sesión', 'Session', 'Sitzung'],
  ['退出后账号密码会从内存清除，OMEMO 私钥仍保存在当前浏览器中。', 'Signing out clears the account password from memory. OMEMO private keys remain in this browser.', '登出後帳戶密碼會從記憶體清除，OMEMO 私密金鑰仍保存在目前瀏覽器中。', '로그아웃하면 계정 비밀번호가 메모리에서 지워지며 OMEMO 개인 키는 이 브라우저에 남습니다.', 'ログアウトするとアカウントのパスワードはメモリから消去され、OMEMO秘密鍵はこのブラウザに残ります。', 'Al cerrar sesión, la contraseña se borra de la memoria. Las claves privadas OMEMO permanecen en este navegador.', 'La déconnexion efface le mot de passe de la mémoire. Les clés privées OMEMO restent dans ce navigateur.', 'Beim Abmelden wird das Kontopasswort aus dem Speicher gelöscht. OMEMO-Privatschlüssel verbleiben in diesem Browser.'],
  ['退出登录', 'Sign out', '登出', '로그아웃', 'ログアウト', 'Cerrar sesión', 'Se déconnecter', 'Abmelden'],

  ['请求失败', 'Request failed', '請求失敗', '요청 실패', 'リクエストに失敗しました', 'Error en la solicitud', 'Échec de la requête', 'Anfrage fehlgeschlagen'],
  ['未知错误', 'Unknown error', '未知錯誤', '알 수 없는 오류', '不明なエラー', 'Error desconocido', 'Erreur inconnue', 'Unbekannter Fehler'],
  ['账号认证失败', 'Account authentication failed', '帳戶驗證失敗', '계정 인증 실패', 'アカウント認証に失敗しました', 'Falló la autenticación de la cuenta', 'Échec de l’authentification du compte', 'Kontoauthentifizierung fehlgeschlagen'],
  ['对方当前不可用', 'The recipient is currently unavailable', '對方目前無法使用', '상대방이 현재 이용할 수 없습니다', '相手は現在利用できません', 'El destinatario no está disponible', 'Le destinataire est indisponible', 'Der Empfänger ist derzeit nicht verfügbar'],
  ['暂不支持这个远程服务器', 'This remote server is not currently supported', '目前不支援此遠端伺服器', '이 원격 서버는 현재 지원되지 않습니다', 'このリモートサーバーは現在サポートされていません', 'Este servidor remoto no está disponible', 'Ce serveur distant n’est pas pris en charge', 'Dieser entfernte Server wird derzeit nicht unterstützt'],
  ['没有找到所需的加密资料', 'Required encryption data was not found', '找不到所需的加密資料', '필요한 암호화 데이터를 찾을 수 없습니다', '必要な暗号化データが見つかりません', 'No se encontraron los datos de cifrado necesarios', 'Les données de chiffrement requises sont introuvables', 'Erforderliche Verschlüsselungsdaten wurden nicht gefunden'],
  ['服务器暂不支持这项操作', 'The server does not currently support this action', '伺服器目前不支援此操作', '서버가 현재 이 작업을 지원하지 않습니다', 'サーバーは現在この操作をサポートしていません', 'El servidor no admite esta acción', 'Le serveur ne prend pas en charge cette action', 'Der Server unterstützt diese Aktion derzeit nicht'],
  ['资源冲突，请重试', 'Resource conflict. Please try again.', '資源衝突，請重試', '리소스 충돌입니다. 다시 시도하세요.', 'リソースが競合しています。もう一度お試しください。', 'Conflicto de recursos. Inténtalo de nuevo.', 'Conflit de ressources. Réessayez.', 'Ressourcenkonflikt. Bitte erneut versuchen.'],
  ['请稍候…', 'Please wait…', '請稍候…', '잠시만 기다려 주세요…', 'お待ちください…', 'Espera…', 'Veuillez patienter…', 'Bitte warten…'],
  ['发布中…', 'Publishing…', '正在發佈…', '게시 중…', '公開中…', 'Publicando…', 'Publication…', 'Wird veröffentlicht…'],
  ['头像已发布到 XMPP 头像节点和 vCard', 'Avatar published to the XMPP avatar node and vCard', '頭像已發佈至 XMPP 頭像節點與 vCard', '아바타가 XMPP 아바타 노드와 vCard에 게시되었습니다', 'アバターをXMPPアバターノードとvCardに公開しました', 'Avatar publicado en el nodo XMPP y la vCard', 'Avatar publié dans le nœud XMPP et la vCard', 'Avatar im XMPP-Avatar-Knoten und in der vCard veröffentlicht'],
  ['网络已断开', 'Network disconnected', '網路已中斷', '네트워크 연결 끊김', 'ネットワークが切断されました', 'Red desconectada', 'Réseau déconnecté', 'Netzwerk getrennt'],
  ['创建账号', 'Create account', '建立帳戶', '계정 만들기', 'アカウントを作成', 'Crear cuenta', 'Créer un compte', 'Konto erstellen'],
  ['两次输入的密码不一致', 'Passwords do not match', '兩次輸入的密碼不一致', '비밀번호가 일치하지 않습니다', 'パスワードが一致しません', 'Las contraseñas no coinciden', 'Les mots de passe ne correspondent pas', 'Passwörter stimmen nicht überein'],
  ['正在创建…', 'Creating…', '正在建立…', '생성 중…', '作成中…', 'Creando…', 'Création…', 'Wird erstellt…'],
  ['账号已创建，可以立即登录。', 'Account created. You can sign in now.', '帳戶已建立，現在可以登入。', '계정이 생성되었습니다. 지금 로그인할 수 있습니다.', 'アカウントを作成しました。すぐにログインできます。', 'Cuenta creada. Ya puedes iniciar sesión.', 'Compte créé. Vous pouvez maintenant vous connecter.', 'Konto erstellt. Du kannst dich jetzt anmelden.'],
  ['正在建立安全会话…', 'Establishing a secure session…', '正在建立安全工作階段…', '보안 세션 설정 중…', '安全なセッションを確立中…', 'Estableciendo una sesión segura…', 'Établissement d’une session sécurisée…', 'Sichere Sitzung wird aufgebaut…'],
  ['正在连接', 'Connecting', '正在連線', '연결 중', '接続中', 'Conectando', 'Connexion', 'Verbindung wird hergestellt'],
  ['在线 · OMEMO 初始化中', 'Online · Initializing OMEMO', '在線 · 正在初始化 OMEMO', '온라인 · OMEMO 초기화 중', 'オンライン · OMEMOを初期化中', 'En línea · Inicializando OMEMO', 'En ligne · Initialisation d’OMEMO', 'Online · OMEMO wird initialisiert'],
  ['连接已断开', 'Connection closed', '連線已中斷', '연결이 끊어졌습니다', '接続が切断されました', 'Conexión cerrada', 'Connexion interrompue', 'Verbindung getrennt'],
  ['在线 · OMEMO 已启用', 'Online · OMEMO enabled', '在線 · OMEMO 已啟用', '온라인 · OMEMO 활성화됨', 'オンライン · OMEMO有効', 'En línea · OMEMO activado', 'En ligne · OMEMO activé', 'Online · OMEMO aktiviert'],
  ['联系人请求已发送', 'Contact request sent', '聯絡人請求已傳送', '연락처 요청 전송됨', '連絡先リクエストを送信しました', 'Solicitud de contacto enviada', 'Demande de contact envoyée', 'Kontaktanfrage gesendet'],
  ['联系人请求已接受', 'Contact request accepted', '聯絡人請求已接受', '연락처 요청 수락됨', '連絡先リクエストを承認しました', 'Solicitud de contacto aceptada', 'Demande de contact acceptée', 'Kontaktanfrage angenommen'],
  ['接受', 'Accept', '接受', '수락', '承認', 'Aceptar', 'Accepter', 'Annehmen'],
  ['身份未公开', 'Identity not disclosed', '身分未公開', '신원 비공개', 'IDは非公開です', 'Identidad no revelada', 'Identité non divulguée', 'Identität nicht offengelegt'],
  ['房主', 'Owner', '房主', '방 소유자', 'オーナー', 'Propietario', 'Propriétaire', 'Eigentümer'],
  ['管理员', 'Administrator', '管理員', '관리자', '管理者', 'Administrador', 'Administrateur', 'Administrator'],
  ['成员', 'Member', '成員', '구성원', 'メンバー', 'Miembro', 'Membre', 'Mitglied'],
  ['尚未收到成员列表。', 'No member list has been received yet.', '尚未收到成員清單。', '아직 구성원 목록을 받지 못했습니다.', 'メンバー一覧はまだ届いていません。', 'Aún no se ha recibido la lista de miembros.', 'La liste des membres n’a pas encore été reçue.', 'Noch keine Mitgliederliste empfangen.'],
  ['已解除屏蔽', 'Contact unblocked', '已解除封鎖', '차단 해제됨', 'ブロックを解除しました', 'Contacto desbloqueado', 'Contact débloqué', 'Kontakt entsperrt'],
  ['已屏蔽此联系人', 'Contact blocked', '已封鎖此聯絡人', '연락처 차단됨', '連絡先をブロックしました', 'Contacto bloqueado', 'Contact bloqué', 'Kontakt blockiert'],
  ['联系人已屏蔽', 'Contact is blocked', '聯絡人已封鎖', '연락처가 차단됨', '連絡先はブロックされています', 'El contacto está bloqueado', 'Le contact est bloqué', 'Kontakt ist blockiert'],
  ['OMEMO 端到端加密', 'OMEMO end-to-end encryption', 'OMEMO 端對端加密', 'OMEMO 종단간 암호화', 'OMEMOエンドツーエンド暗号化', 'Cifrado de extremo a extremo OMEMO', 'Chiffrement de bout en bout OMEMO', 'OMEMO-Ende-zu-Ende-Verschlüsselung'],
  ['正在加入群聊', 'Joining group', '正在加入群聊', '그룹 참여 중', 'グループに参加中', 'Entrando al grupo', 'Connexion au groupe', 'Gruppe wird betreten'],
  ['在线', 'Online', '在線', '온라인', 'オンライン', 'En línea', 'En ligne', 'Online'],
  ['离开', 'Away', '離開', '자리 비움', '離席中', 'Ausente', 'Absent', 'Abwesend'],
  ['请勿打扰', 'Do not disturb', '請勿打擾', '방해 금지', '取り込み中', 'No molestar', 'Ne pas déranger', 'Nicht stören'],
  ['加密中…', 'Encrypting…', '正在加密…', '암호화 중…', '暗号化中…', 'Cifrando…', 'Chiffrement…', 'Wird verschlüsselt…'],
  ['加密上传中…', 'Encrypting and uploading…', '正在加密並上傳…', '암호화 및 업로드 중…', '暗号化してアップロード中…', 'Cifrando y subiendo…', 'Chiffrement et téléversement…', 'Wird verschlüsselt und hochgeladen…'],
  ['解密中…', 'Decrypting…', '正在解密…', '복호화 중…', '復号中…', 'Descifrando…', 'Déchiffrement…', 'Wird entschlüsselt…'],
  ['解密并下载', 'Decrypt and download', '解密並下載', '복호화 및 다운로드', '復号してダウンロード', 'Descifrar y descargar', 'Déchiffrer et télécharger', 'Entschlüsseln und herunterladen'],
  ['解密失败', 'Decryption failed', '解密失敗', '복호화 실패', '復号に失敗しました', 'Falló el descifrado', 'Échec du déchiffrement', 'Entschlüsselung fehlgeschlagen'],
  ['◇ 端到端加密', '◇ End-to-end encrypted', '◇ 端對端加密', '◇ 종단간 암호화', '◇ エンドツーエンド暗号化', '◇ Cifrado de extremo a extremo', '◇ Chiffré de bout en bout', '◇ Ende-zu-Ende-verschlüsselt'],
  ['未加密', 'Not encrypted', '未加密', '암호화되지 않음', '暗号化されていません', 'Sin cifrar', 'Non chiffré', 'Nicht verschlüsselt'],
  ['检查中', 'Checking', '正在檢查', '확인 중', '確認中', 'Comprobando', 'Vérification', 'Wird geprüft'],
  ['未找到加密设备', 'No encryption devices found', '找不到加密裝置', '암호화 장치를 찾을 수 없음', '暗号化端末が見つかりません', 'No se encontraron dispositivos de cifrado', 'Aucun appareil de chiffrement trouvé', 'Keine Verschlüsselungsgeräte gefunden'],
  ['OMEMO 端到端加密已就绪', 'OMEMO end-to-end encryption is ready', 'OMEMO 端對端加密已就緒', 'OMEMO 종단간 암호화 준비 완료', 'OMEMOエンドツーエンド暗号化の準備ができました', 'El cifrado de extremo a extremo OMEMO está listo', 'Le chiffrement de bout en bout OMEMO est prêt', 'OMEMO-Ende-zu-Ende-Verschlüsselung ist bereit'],
  ['无法加密', 'Cannot encrypt', '無法加密', '암호화할 수 없음', '暗号化できません', 'No se puede cifrar', 'Chiffrement impossible', 'Verschlüsselung nicht möglich'],
  ['暂时无法安全发送', 'Secure sending is temporarily unavailable', '暫時無法安全傳送', '현재 안전하게 보낼 수 없음', '現在安全に送信できません', 'El envío seguro no está disponible temporalmente', 'L’envoi sécurisé est temporairement indisponible', 'Sicheres Senden ist vorübergehend nicht verfügbar'],
  ['尚未建立加密会话', 'No encrypted session has been established', '尚未建立加密工作階段', '암호화 세션이 설정되지 않음', '暗号化セッションが確立されていません', 'No se ha establecido una sesión cifrada', 'Aucune session chiffrée n’est établie', 'Keine verschlüsselte Sitzung aufgebaut'],
  ['正在读取设备…', 'Reading devices…', '正在讀取裝置…', '장치 읽는 중…', '端末を読み込み中…', 'Leyendo dispositivos…', 'Lecture des appareils…', 'Geräte werden gelesen…'],
  ['首次使用即信任（TOFU）', 'Trust on first use (TOFU)', '首次使用即信任（TOFU）', '최초 사용 시 신뢰(TOFU)', '初回利用時に信頼（TOFU）', 'Confianza en el primer uso (TOFU)', 'Confiance à la première utilisation (TOFU)', 'Vertrauen bei erster Nutzung (TOFU)'],
  ['不可用', 'Unavailable', '無法使用', '사용할 수 없음', '利用できません', 'No disponible', 'Indisponible', 'Nicht verfügbar'],
  ['无法读取指纹', 'Fingerprint cannot be read', '無法讀取指紋', '지문을 읽을 수 없음', 'フィンガープリントを読み取れません', 'No se puede leer la huella', 'Impossible de lire l’empreinte', 'Fingerabdruck kann nicht gelesen werden'],
  ['对方尚未发布 OMEMO 设备。', 'The recipient has not published any OMEMO devices.', '對方尚未發佈 OMEMO 裝置。', '상대방이 아직 OMEMO 장치를 게시하지 않았습니다.', '相手はまだOMEMO端末を公開していません。', 'El destinatario aún no ha publicado dispositivos OMEMO.', 'Le destinataire n’a encore publié aucun appareil OMEMO.', 'Der Empfänger hat noch keine OMEMO-Geräte veröffentlicht.'],
  ['正在重新连接', 'Reconnecting', '正在重新連線', '다시 연결 중', '再接続中', 'Reconectando', 'Reconnexion', 'Verbindung wird wiederhergestellt'],
  ['已安全退出；本机 OMEMO 私钥仍保留在此浏览器中。', 'Signed out securely; local OMEMO private keys remain in this browser.', '已安全登出；本機 OMEMO 私密金鑰仍保留在此瀏覽器中。', '안전하게 로그아웃했습니다. 로컬 OMEMO 개인 키는 이 브라우저에 남아 있습니다.', '安全にログアウトしました。ローカルOMEMO秘密鍵はこのブラウザに残ります。', 'Sesión cerrada de forma segura; las claves privadas OMEMO locales permanecen en este navegador.', 'Déconnexion sécurisée ; les clés privées OMEMO locales restent dans ce navigateur.', 'Sicher abgemeldet; lokale OMEMO-Privatschlüssel verbleiben in diesem Browser.'],

  ['在线会话', 'Online sessions', '線上工作階段', '온라인 세션', 'オンラインセッション', 'Sesiones en línea', 'Sessions en ligne', 'Online-Sitzungen'],
  ['密文归档', 'Encrypted archive', '密文封存', '암호문 보관', '暗号文アーカイブ', 'Archivo cifrado', 'Archive chiffrée', 'Verschlüsseltes Archiv'],
  ['离线队列', 'Offline queue', '離線佇列', '오프라인 대기열', 'オフラインキュー', 'Cola sin conexión', 'File hors ligne', 'Offline-Warteschlange'],
  ['群聊房间', 'Group rooms', '群聊房間', '그룹 방', 'グループルーム', 'Salas de grupo', 'Salons de groupe', 'Gruppenräume'],
  ['群聊在线成员', 'Online group members', '群聊線上成員', '온라인 그룹 구성원', 'オンラインのグループメンバー', 'Miembros de grupo en línea', 'Membres de groupe en ligne', 'Online-Gruppenmitglieder'],
  ['已上传文件', 'Uploaded files', '已上傳檔案', '업로드된 파일', 'アップロード済みファイル', 'Archivos subidos', 'Fichiers téléversés', 'Hochgeladene Dateien'],
  ['推送订阅', 'Push subscriptions', '推播訂閱', '푸시 구독', 'プッシュ購読', 'Suscripciones push', 'Abonnements push', 'Push-Abonnements'],
  ['联邦投递', 'Federated deliveries', '聯邦傳送', '연합 전달', 'フェデレーション配信', 'Entregas federadas', 'Livraisons fédérées', 'Föderierte Zustellungen'],
  ['联邦失败', 'Federation failures', '聯邦失敗', '연합 실패', 'フェデレーション失敗', 'Fallos de federación', 'Échecs de fédération', 'Föderationsfehler'],
  ['用户', 'User', '使用者', '사용자', 'ユーザー', 'Usuario', 'Utilisateur', 'Benutzer'],
  ['已停用', 'Disabled', '已停用', '비활성화됨', '無効', 'Desactivado', 'Désactivé', 'Deaktiviert'],
  ['正常', 'Active', '正常', '활성', '有効', 'Activo', 'Actif', 'Aktiv'],
  ['启用', 'Enable', '啟用', '활성화', '有効化', 'Activar', 'Activer', 'Aktivieren'],
  ['停用', 'Disable', '停用', '비활성화', '無効化', 'Desactivar', 'Désactiver', 'Deaktivieren'],
  ['撤销管理', 'Remove administrator', '撤銷管理員', '관리자 권한 해제', '管理者権限を解除', 'Quitar administración', 'Retirer les droits administrateur', 'Administratorrechte entziehen'],
  ['设为管理', 'Make administrator', '設為管理員', '관리자로 설정', '管理者に設定', 'Hacer administrador', 'Rendre administrateur', 'Zum Administrator machen'],
  ['该账户没有管理员权限', 'This account does not have administrator privileges', '此帳戶沒有管理員權限', '이 계정에는 관리자 권한이 없습니다', 'このアカウントには管理者権限がありません', 'Esta cuenta no tiene privilegios de administrador', 'Ce compte ne dispose pas des privilèges administrateur', 'Dieses Konto hat keine Administratorrechte'],
  ['Northstar XMPP 服务入口与管理后台', 'Northstar XMPP service and administration', 'Northstar XMPP 服務入口與管理後台', 'Northstar XMPP 서비스 및 관리', 'Northstar XMPP サービスと管理', 'Servicio y administración de Northstar XMPP', 'Service et administration Northstar XMPP', 'Northstar XMPP-Dienst und Verwaltung'],
  ['Northstar 私密 XMPP 网页客户端', 'Northstar private XMPP web client', 'Northstar 私密 XMPP 網頁客戶端', 'Northstar 비공개 XMPP 웹 클라이언트', 'Northstar プライベート XMPP Webクライアント', 'Cliente web XMPP privado de Northstar', 'Client web XMPP privé Northstar', 'Privater Northstar XMPP-Webclient'],
  ['Northstar 私密聊天', 'Northstar private chat', 'Northstar 私密聊天', 'Northstar 비공개 채팅', 'Northstar プライベートチャット', 'Chat privado de Northstar', 'Messagerie privée Northstar', 'Privater Northstar-Chat'],
  ['头像必须是 PNG、JPEG 或 WebP，且不超过 256 KiB', 'The avatar must be PNG, JPEG or WebP and no larger than 256 KiB', '頭像必須是 PNG、JPEG 或 WebP，且不超過 256 KiB', '아바타는 PNG, JPEG 또는 WebP 형식이며 256 KiB 이하여야 합니다', 'アバターは PNG、JPEG、WebP のいずれかで、256 KiB 以下にしてください', 'El avatar debe ser PNG, JPEG o WebP y no superar 256 KiB', 'L’avatar doit être au format PNG, JPEG ou WebP et ne pas dépasser 256 Kio', 'Der Avatar muss PNG, JPEG oder WebP sein und darf höchstens 256 KiB groß sein'],
  ['服务器已关闭开放注册', 'Open registration is disabled on this server', '伺服器已關閉開放註冊', '이 서버에서는 공개 가입이 비활성화되어 있습니다', 'このサーバーでは公開登録が無効です', 'El registro abierto está desactivado en este servidor', 'L’inscription ouverte est désactivée sur ce serveur', 'Die offene Registrierung ist auf diesem Server deaktiviert'],
  ['不能把自己添加为联系人', 'You cannot add yourself as a contact', '不能將自己加為聯絡人', '자신을 연락처로 추가할 수 없습니다', '自分自身を連絡先に追加することはできません', 'No puedes añadirte como contacto', 'Vous ne pouvez pas vous ajouter comme contact', 'Du kannst dich nicht selbst als Kontakt hinzufügen'],
  ['房间名称或昵称格式不正确', 'The room name or nickname has an invalid format', '房間名稱或暱稱格式不正確', '방 이름 또는 닉네임 형식이 올바르지 않습니다', 'ルーム名またはニックネームの形式が正しくありません', 'El nombre de la sala o el apodo tiene un formato no válido', 'Le nom du salon ou le pseudonyme a un format incorrect', 'Raumname oder Spitzname hat ein ungültiges Format'],
  ['群聊中还没有其他成员', 'There are no other members in this group yet', '群聊中還沒有其他成員', '아직 그룹에 다른 멤버가 없습니다', 'グループにはまだ他のメンバーがいません', 'Aún no hay otros miembros en este grupo', 'Il n’y a pas encore d’autres membres dans ce groupe', 'In dieser Gruppe gibt es noch keine weiteren Mitglieder'],
  ['群聊中还没有其他可加密的成员', 'There are no other encryptable members in this group yet', '群聊中還沒有其他可加密的成員', '아직 그룹에 암호화할 수 있는 다른 멤버가 없습니다', 'グループにはまだ暗号化できる他のメンバーがいません', 'Aún no hay otros miembros cifrables en este grupo', 'Il n’y a pas encore d’autres membres pouvant être chiffrés dans ce groupe', 'In dieser Gruppe gibt es noch keine weiteren verschlüsselbaren Mitglieder'],
  ['发送中…', 'Sending…', '傳送中…', '보내는 중…', '送信中…', 'Enviando…', 'Envoi…', 'Wird gesendet…'],
  ['加入中…', 'Joining…', '加入中…', '참여 중…', '参加中…', 'Uniéndose…', 'Connexion…', 'Beitritt…'],
  ['解除中…', 'Unblocking…', '解除中…', '차단 해제 중…', 'ブロック解除中…', 'Desbloqueando…', 'Déblocage…', 'Blockierung wird aufgehoben…'],
  ['屏蔽中…', 'Blocking…', '封鎖中…', '차단 중…', 'ブロック中…', 'Bloqueando…', 'Blocage…', 'Wird blockiert…'],
  ['服务器返回了无法解析的 XML', 'The server returned XML that could not be parsed'],
  ['XMPP 请求失败', 'XMPP request failed'],
  ['无法连接 XMPP WebSocket', 'Could not connect to the XMPP WebSocket'],
  ['XMPP 尚未连接', 'XMPP is not connected'],
  ['XMPP 请求超时', 'The XMPP request timed out'],
  ['用户名或密码错误', 'Incorrect username or password'],
  ['XMPP 连接已关闭', 'The XMPP connection has closed'],
  ['上传服务返回了无效槽位', 'The upload service returned an invalid slot'],
  ['无法打开本机安全存储', 'Could not open secure local storage'],
  ['本机存储操作失败', 'The local storage operation failed'],
  ['本机存储操作被中止', 'The local storage operation was aborted'],
  ['读取本机存储失败', 'Could not read local storage'],
  ['对方设备没有可用的 OMEMO 预密钥', 'The recipient device has no available OMEMO pre-key'],
  ['OMEMO 内容密钥长度无效', 'The OMEMO content key has an invalid length'],
  ['OMEMO 完整性校验失败', 'OMEMO integrity verification failed'],
  ['OMEMO 明文结构无效', 'The OMEMO plaintext structure is invalid'],
  ['缺少 OMEMO SCE 信封', 'The OMEMO SCE envelope is missing'],
  ['OMEMO 发件人校验失败', 'OMEMO sender verification failed'],
  ['加密消息没有正文', 'The encrypted message has no body'],
  ['无法生成唯一的 OMEMO 设备 ID', 'Could not generate a unique OMEMO device ID'],
  ['对方尚未发布 OMEMO 设备，不能安全发送消息', 'The recipient has not published an OMEMO device, so the message cannot be sent securely'],
  ['无法建立对方的 OMEMO 会话', 'Could not establish an OMEMO session with the recipient'],
  ['OMEMO 尚未初始化', 'OMEMO has not been initialized'],
  ['这条消息没有加密给当前设备', 'This message was not encrypted for the current device'],
  ['邀请码（可选）', 'Invitation token (optional)', '邀請碼（選填）', '초대 토큰(선택 사항)', '招待トークン（任意）', 'Token de invitación (opcional)', 'Jeton d’invitation (facultatif)', 'Einladungstoken (optional)'],
  ['邀请码（必填）', 'Invitation token (required)', '邀請碼（必填）', '초대 토큰(필수)', '招待トークン（必須）', 'Token de invitación (obligatorio)', 'Jeton d’invitation (obligatoire)', 'Einladungstoken (erforderlich)'],
  ['举报并选取聊天记录', 'Report and select chat records', '檢舉並選取聊天記錄', '신고하고 채팅 기록 선택', '通報してチャット履歴を選択', 'Denunciar y seleccionar mensajes', 'Signaler et sélectionner des messages', 'Melden und Chatnachrichten auswählen'],
  ['举报与申诉', 'Reports and appeals', '檢舉與申訴', '신고 및 이의 제기', '通報と異議申立て', 'Denuncias y apelaciones', 'Signalements et recours', 'Meldungen und Einsprüche'],
  ['查看举报处理结果，并在已处理的举报上提交一次申诉。申诉采用更严格的账号限流和工作量证明。', 'Review report outcomes and submit one appeal for a resolved report. Appeals use stricter account rate limits and proof of work.', '查看檢舉處理結果，並可針對已處理的檢舉提交一次申訴。申訴採用更嚴格的帳戶速率限制與工作量證明。', '신고 처리 결과를 확인하고 처리된 신고에 한 번 이의를 제기할 수 있습니다. 이의 제기에는 더 엄격한 계정 속도 제한과 작업 증명이 적용됩니다.', '通報の処理結果を確認し、処理済みの通報に1回異議を申し立てられます。異議申立てにはより厳しいアカウント制限とPoWが適用されます。', 'Revisa los resultados y presenta una apelación por cada denuncia resuelta. Las apelaciones tienen límites de cuenta y prueba de trabajo más estrictos.', 'Consultez les décisions et déposez un recours par signalement résolu. Les recours appliquent des limites de compte et une preuve de travail plus strictes.', 'Prüfe Ergebnisse und lege pro abgeschlossener Meldung einmal Einspruch ein. Dafür gelten strengere Kontolimits und Arbeitsnachweise.'],
  ['查看举报与申诉', 'View reports and appeals', '查看檢舉與申訴', '신고 및 이의 제기 보기', '通報と異議申立てを表示', 'Ver denuncias y apelaciones', 'Voir les signalements et recours', 'Meldungen und Einsprüche anzeigen'],
  ['举报会话', 'Report conversation', '檢舉會話', '대화 신고', '会話を通報', 'Denunciar conversación', 'Signaler la conversation', 'Unterhaltung melden'],
  ['请选择 1–20 条聊天记录作为证据。所选消息的明文会在你明确提交后发送给管理人员，即使原消息使用了 OMEMO；未选中的消息不会提交。', 'Select 1–20 chat records as evidence. After explicit submission, the plaintext of selected messages is sent to moderators even if the originals used OMEMO; unselected messages are not submitted.', '請選擇 1–20 條聊天記錄作為證據。明確提交後，所選訊息的明文會傳送給管理人員，即使原訊息使用 OMEMO；未選訊息不會提交。', '증거로 채팅 기록 1~20개를 선택하세요. 명시적으로 제출하면 원본이 OMEMO를 사용했더라도 선택한 메시지의 평문이 관리자에게 전송되며 선택하지 않은 메시지는 제출되지 않습니다.', '証拠として1～20件の履歴を選択してください。明示的に送信すると、元のメッセージがOMEMOでも選択した平文が管理者へ送られ、未選択のメッセージは送信されません。', 'Selecciona entre 1 y 20 mensajes. Al enviar, su texto en claro se remitirá a moderación aunque los originales usaran OMEMO; los no seleccionados no se enviarán.', 'Sélectionnez 1 à 20 messages. Après confirmation, leur texte en clair sera transmis à la modération même si les originaux utilisaient OMEMO ; les autres ne seront pas envoyés.', 'Wähle 1–20 Nachrichten als Beleg. Nach ausdrücklichem Absenden wird deren Klartext auch bei OMEMO an die Moderation gesendet; nicht ausgewählte Nachrichten werden nicht übertragen.'],
  ['举报类型', 'Report category', '檢舉類型', '신고 유형', '通報の種類', 'Categoría', 'Catégorie', 'Meldekategorie'],
  ['垃圾信息', 'Spam', '垃圾訊息', '스팸', 'スパム', 'Spam', 'Spam', 'Spam'],
  ['骚扰', 'Harassment', '騷擾', '괴롭힘', '嫌がらせ', 'Acoso', 'Harcèlement', 'Belästigung'],
  ['威胁', 'Threat', '威脅', '위협', '脅迫', 'Amenaza', 'Menace', 'Drohung'],
  ['冒充身份', 'Impersonation', '冒充身分', '사칭', 'なりすまし', 'Suplantación', 'Usurpation d’identité', 'Identitätsmissbrauch'],
  ['违法内容', 'Illegal content', '違法內容', '불법 콘텐츠', '違法なコンテンツ', 'Contenido ilegal', 'Contenu illégal', 'Illegale Inhalte'],
  ['其他', 'Other', '其他', '기타', 'その他', 'Otro', 'Autre', 'Sonstiges'],
  ['选取聊天记录', 'Select chat records', '選取聊天記錄', '채팅 기록 선택', 'チャット履歴を選択', 'Seleccionar mensajes', 'Sélectionner des messages', 'Chatnachrichten auswählen'],
  ['补充说明（可选）', 'Additional details (optional)', '補充說明（選填）', '추가 설명(선택 사항)', '補足説明（任意）', 'Detalles adicionales (opcional)', 'Informations complémentaires (facultatif)', 'Zusätzliche Angaben (optional)'],
  ['举报需要工作量证明。频繁举报会按台阶提高工作量和等待时间；限制有上限，停止频繁操作后会逐级冷却并恢复。最大工作量设计目标约为中端手机 8 秒。', 'Reports require proof of work. Frequent reports increase work and waiting in steps; limits have a maximum and gradually cool down after frequent activity stops. Maximum work targets about 8 seconds on a midrange phone.', '檢舉需要工作量證明。頻繁檢舉會分級提高工作量與等待時間；限制設有上限，停止頻繁操作後會逐級冷卻恢復。最大工作量目標約為中階手機 8 秒。', '신고에는 작업 증명이 필요합니다. 잦은 신고는 작업량과 대기 시간이 단계적으로 증가하며 상한이 있고 활동을 멈추면 점차 완화됩니다. 최대 작업량은 중급 휴대전화에서 약 8초를 목표로 합니다.', '通報にはPoWが必要です。頻繁な通報では作業量と待機時間が段階的に増え、上限があります。操作を止めると徐々に通常へ戻ります。最大作業量は中級スマートフォンで約8秒が目安です。', 'Las denuncias requieren prueba de trabajo. La frecuencia eleva por niveles el trabajo y la espera; hay un máximo y el nivel desciende gradualmente al parar. El máximo busca unos 8 segundos en un móvil de gama media.', 'Les signalements exigent une preuve de travail. Leur fréquence augmente par paliers le travail et l’attente ; un plafond existe et le niveau redescend progressivement après l’arrêt. Le maximum vise environ 8 secondes sur un téléphone de milieu de gamme.', 'Meldungen erfordern einen Arbeitsnachweis. Häufige Meldungen erhöhen Arbeit und Wartezeit stufenweise; es gibt eine Obergrenze und nach Ende der Aktivität sinkt die Stufe allmählich. Das Maximum zielt auf etwa 8 Sekunden auf einem Mittelklasse-Handy.'],
  ['计算并提交举报', 'Calculate and submit report', '計算並提交檢舉', '계산 후 신고 제출', '計算して通報を送信', 'Calcular y enviar denuncia', 'Calculer et envoyer le signalement', 'Berechnen und Meldung senden'],
  ['举报处理记录', 'Report outcomes', '檢舉處理記錄', '신고 처리 기록', '通報の処理履歴', 'Resultados de denuncias', 'Résultats des signalements', 'Meldeergebnisse'],
  ['每份举报只能申诉一次。申诉的账号限流和工作量证明比普通举报更严格，且同样会逐级冷却。', 'Each report can be appealed once. Appeals use stricter account limits and proof of work than reports, with the same gradual cooldown.', '每份檢舉只能申訴一次。申訴的帳戶速率限制與工作量證明比一般檢舉更嚴格，並同樣會逐級冷卻。', '각 신고는 한 번만 이의를 제기할 수 있습니다. 이의 제기는 신고보다 더 엄격한 계정 제한과 작업 증명을 사용하며 동일하게 단계적으로 완화됩니다.', '各通報への異議申立ては1回だけです。通常の通報より厳しいアカウント制限とPoWが適用され、同様に段階的に緩和されます。', 'Cada denuncia admite una apelación. Las apelaciones tienen límites de cuenta y prueba de trabajo más estrictos y el mismo enfriamiento gradual.', 'Chaque signalement ne peut faire l’objet que d’un recours. Les limites de compte et la preuve de travail sont plus strictes, avec le même retour progressif.', 'Jede Meldung kann einmal angefochten werden. Für Einsprüche gelten strengere Kontolimits und Arbeitsnachweise mit derselben stufenweisen Abkühlung.'],
  ['计算并提交申诉', 'Calculate and submit appeal', '計算並提交申訴', '계산 후 이의 제기 제출', '計算して異議申立てを送信', 'Calcular y enviar apelación', 'Calculer et envoyer le recours', 'Berechnen und Einspruch senden'],
  ['注册邀请码', 'Registration invitations', '註冊邀請碼', '가입 초대', '登録招待', 'Invitaciones de registro', 'Invitations d’inscription', 'Registrierungseinladungen'],
  ['用途标签', 'Purpose label', '用途標籤', '용도 라벨', '用途ラベル', 'Etiqueta de uso', 'Libellé d’usage', 'Zweckbezeichnung'],
  ['例如：社区成员', 'For example: community member', '例如：社群成員', '예: 커뮤니티 회원', '例：コミュニティメンバー', 'Por ejemplo: miembro de la comunidad', 'Par exemple : membre de la communauté', 'Zum Beispiel: Community-Mitglied'],
  ['最多使用次数', 'Maximum uses', '最多使用次數', '최대 사용 횟수', '最大使用回数', 'Usos máximos', 'Nombre maximal d’utilisations', 'Maximale Verwendungen'],
  ['有效小时数', 'Valid hours', '有效小時數', '유효 시간', '有効時間', 'Horas de validez', 'Durée de validité en heures', 'Gültigkeitsstunden'],
  ['创建邀请码', 'Create invitation', '建立邀請碼', '초대 만들기', '招待を作成', 'Crear invitación', 'Créer une invitation', 'Einladung erstellen'],
  ['举报与申诉队列', 'Reports and appeals queue', '檢舉與申訴佇列', '신고 및 이의 제기 대기열', '通報と異議申立てキュー', 'Cola de denuncias y apelaciones', 'File des signalements et recours', 'Meldungs- und Einspruchswarteschlange'],
  ['仅显示用户明确选取并提交的聊天记录', 'Only chat records explicitly selected and submitted by users are shown', '僅顯示使用者明確選取並提交的聊天記錄', '사용자가 명시적으로 선택하여 제출한 채팅 기록만 표시됩니다', 'ユーザーが明示的に選択して送信した履歴のみ表示します', 'Solo se muestran los mensajes seleccionados y enviados explícitamente', 'Seuls les messages explicitement sélectionnés et envoyés sont affichés', 'Nur ausdrücklich ausgewählte und eingereichte Chatnachrichten werden angezeigt'],
  ['账户管理', 'Account administration', '帳戶管理', '계정 관리', 'アカウント管理', 'Administración de cuentas', 'Administration des comptes', 'Kontoverwaltung'],
  ['举报状态', 'Report status', '檢舉狀態', '신고 상태', '通報状況', 'Estado de la denuncia', 'État du signalement', 'Meldestatus'],
  ['处理说明', 'Resolution details', '處理說明', '처리 설명', '処理説明', 'Detalles de la resolución', 'Détails de la décision', 'Bearbeitungshinweise'],
  ['保存处理结果', 'Save report outcome', '儲存處理結果', '처리 결과 저장', '処理結果を保存', 'Guardar resultado', 'Enregistrer la décision', 'Ergebnis speichern'],
  ['申诉状态', 'Appeal status', '申訴狀態', '이의 제기 상태', '異議申立て状況', 'Estado de la apelación', 'État du recours', 'Einspruchsstatus'],
  ['申诉处理说明', 'Appeal resolution details', '申訴處理說明', '이의 제기 처리 설명', '異議申立ての処理説明', 'Detalles de la apelación', 'Détails de la décision du recours', 'Einspruchsbearbeitung'],
  ['保存申诉处理', 'Save appeal outcome', '儲存申訴處理', '이의 제기 처리 저장', '異議申立て結果を保存', 'Guardar resultado de apelación', 'Enregistrer la décision du recours', 'Einspruchsergebnis speichern'],
  ['待处理举报', 'Pending reports', '待處理檢舉', '대기 중인 신고', '未処理の通報', 'Denuncias pendientes', 'Signalements en attente', 'Offene Meldungen'],
  ['待处理申诉', 'Pending appeals', '待處理申訴', '대기 중인 이의 제기', '未処理の異議申立て', 'Apelaciones pendientes', 'Recours en attente', 'Offene Einsprüche'],
  ['有效邀请码', 'Active invitations', '有效邀請碼', '유효한 초대', '有効な招待', 'Invitaciones activas', 'Invitations actives', 'Aktive Einladungen'],
  ['触发限制', 'Rate-limited operations', '觸發限制', '제한된 작업', '制限された操作', 'Operaciones limitadas', 'Opérations limitées', 'Begrenzte Vorgänge'],
  ['已提交', 'Submitted', '已提交', '제출됨', '送信済み', 'Enviada', 'Envoyé', 'Eingereicht'],
  ['处理中', 'Under review', '處理中', '검토 중', '審査中', 'En revisión', 'En cours d’examen', 'In Prüfung'],
  ['已采取措施', 'Action taken', '已採取措施', '조치 완료', '対応済み', 'Medidas tomadas', 'Mesures prises', 'Maßnahmen ergriffen'],
  ['未支持举报', 'Report not upheld', '未支持檢舉', '신고 기각', '通報は認められませんでした', 'Denuncia no aceptada', 'Signalement non retenu', 'Meldung nicht bestätigt'],
  ['已关闭', 'Closed', '已關閉', '종료됨', 'クローズ済み', 'Cerrada', 'Fermé', 'Geschlossen'],
  ['申诉成立', 'Appeal upheld', '申訴成立', '이의 제기 인용', '異議申立て成立', 'Apelación aceptada', 'Recours accepté', 'Einspruch stattgegeben'],
  ['申诉未成立', 'Appeal denied', '申訴未成立', '이의 제기 기각', '異議申立て却下', 'Apelación denegada', 'Recours rejeté', 'Einspruch abgelehnt'],
  ['撤销', 'Revoke', '撤銷', '취소', '無効化', 'Revocar', 'Révoquer', 'Widerrufen'],
  ['有效', 'Active', '有效', '유효', '有効', 'Activa', 'Actif', 'Aktiv'],
  ['不可用', 'Unavailable', '不可用', '사용 불가', '利用不可', 'No disponible', 'Indisponible', 'Nicht verfügbar'],
  ['我', 'Me', '我', '나', '自分', 'Yo', 'Moi', 'Ich'],
  ['当前没有可以提交的聊天记录。', 'There are no chat records available to submit.', '目前沒有可提交的聊天記錄。', '제출할 수 있는 채팅 기록이 없습니다.', '送信できるチャット履歴がありません。', 'No hay mensajes disponibles para enviar.', 'Aucun message ne peut être envoyé.', 'Es sind keine Chatnachrichten zum Einreichen vorhanden.'],
  ['请至少选择一条聊天记录。', 'Select at least one chat record.', '請至少選擇一條聊天記錄。', '채팅 기록을 하나 이상 선택하세요.', 'チャット履歴を1件以上選択してください。', 'Selecciona al menos un mensaje.', 'Sélectionnez au moins un message.', 'Wähle mindestens eine Chatnachricht aus.'],
  ['正在计算…', 'Calculating…', '正在計算…', '계산 중…', '計算中…', 'Calculando…', 'Calcul en cours…', 'Wird berechnet…'],
  ['举报已提交，管理人员可以看到你选取的聊天记录。', 'Report submitted. Moderators can now see the chat records you selected.', '檢舉已提交，管理人員現在可以看到你選取的聊天記錄。', '신고가 제출되었습니다. 관리자가 선택한 채팅 기록을 볼 수 있습니다.', '通報を送信しました。管理者は選択したチャット履歴を確認できます。', 'Denuncia enviada. Moderación puede ver los mensajes seleccionados.', 'Signalement envoyé. La modération peut voir les messages sélectionnés.', 'Meldung eingereicht. Die Moderation kann die ausgewählten Chatnachrichten sehen.'],
  ['正在读取举报记录…', 'Loading report records…', '正在讀取檢舉記錄…', '신고 기록 불러오는 중…', '通報履歴を読み込み中…', 'Cargando denuncias…', 'Chargement des signalements…', 'Meldungen werden geladen…'],
  ['处理结果：', 'Outcome: ', '處理結果：', '처리 결과: ', '処理結果：', 'Resultado: ', 'Décision : ', 'Ergebnis: '],
  ['申诉结果：', 'Appeal outcome: ', '申訴結果：', '이의 제기 결과: ', '異議申立て結果：', 'Resultado de la apelación: ', 'Décision du recours : ', 'Einspruchsergebnis: '],
  ['说明为什么对处理结果不满意（至少 20 个字符）', 'Explain why you disagree with the outcome (at least 20 characters)', '說明為何不滿意處理結果（至少 20 個字元）', '처리 결과에 동의하지 않는 이유를 설명하세요(20자 이상)', '処理結果に同意できない理由を説明してください（20文字以上）', 'Explica por qué no estás de acuerdo (al menos 20 caracteres)', 'Expliquez votre désaccord (au moins 20 caractères)', 'Erkläre die Ablehnung des Ergebnisses (mindestens 20 Zeichen)'],
  ['你还没有提交过举报。', 'You have not submitted any reports.', '你尚未提交任何檢舉。', '제출한 신고가 없습니다.', 'まだ通報を送信していません。', 'No has enviado ninguna denuncia.', 'Vous n’avez envoyé aucun signalement.', 'Du hast noch keine Meldung eingereicht.'],
  ['申诉理由至少需要 20 个字符。', 'The appeal reason must be at least 20 characters.', '申訴理由至少需要 20 個字元。', '이의 제기 사유는 20자 이상이어야 합니다.', '異議申立ての理由は20文字以上必要です。', 'El motivo debe tener al menos 20 caracteres.', 'Le motif du recours doit contenir au moins 20 caractères.', 'Die Einspruchsbegründung muss mindestens 20 Zeichen lang sein.'],
  ['正在严格校验…', 'Applying strict checks…', '正在進行嚴格校驗…', '엄격한 검사 진행 중…', '厳格な確認中…', 'Aplicando controles estrictos…', 'Contrôles stricts en cours…', 'Strenge Prüfungen laufen…'],
  ['申诉已提交。', 'Appeal submitted.', '申訴已提交。', '이의 제기가 제출되었습니다.', '異議申立てを送信しました。', 'Apelación enviada.', 'Recours envoyé.', 'Einspruch eingereicht.'],
  ['服务器更新并重启后启用', 'Enabled after the server update and restart', '伺服器更新並重新啟動後啟用', '서버 업데이트 및 재시작 후 활성화', 'サーバーの更新と再起動後に有効', 'Disponible tras actualizar y reiniciar el servidor', 'Activé après la mise à jour et le redémarrage du serveur', 'Nach Serveraktualisierung und Neustart verfügbar'],
  ['服务器更新并重启后启用邀请码管理。', 'Invitation management is enabled after the server update and restart.', '伺服器更新並重新啟動後會啟用邀請碼管理。', '서버 업데이트 및 재시작 후 초대 관리가 활성화됩니다.', 'サーバーの更新と再起動後に招待管理が有効になります。', 'La gestión de invitaciones se habilita tras actualizar y reiniciar el servidor.', 'La gestion des invitations sera activée après la mise à jour et le redémarrage.', 'Die Einladungsverwaltung wird nach Aktualisierung und Neustart aktiviert.'],
  ['服务器更新并重启后启用举报队列。', 'The report queue is enabled after the server update and restart.', '伺服器更新並重新啟動後會啟用檢舉佇列。', '서버 업데이트 및 재시작 후 신고 대기열이 활성화됩니다.', 'サーバーの更新と再起動後に通報キューが有効になります。', 'La cola de denuncias se habilita tras actualizar y reiniciar el servidor.', 'La file des signalements sera activée après la mise à jour et le redémarrage.', 'Die Meldungswarteschlange wird nach Aktualisierung und Neustart aktiviert.'],
  ['尚未创建邀请码。', 'No invitations have been created.', '尚未建立邀請碼。', '생성된 초대가 없습니다.', '招待はまだ作成されていません。', 'No se han creado invitaciones.', 'Aucune invitation n’a été créée.', 'Es wurden noch keine Einladungen erstellt.'],
  ['当前没有举报。', 'There are currently no reports.', '目前沒有檢舉。', '현재 신고가 없습니다.', '現在、通報はありません。', 'No hay denuncias.', 'Il n’y a actuellement aucun signalement.', 'Derzeit gibt es keine Meldungen.'],
  ['时间未知', 'Time unknown', '時間未知', '시간 알 수 없음', '時刻不明', 'Hora desconocida', 'Heure inconnue', 'Zeit unbekannt'],
  ['由举报人从端到端加密会话中选择并解密提交', 'Selected, decrypted and submitted by the reporter from an end-to-end encrypted conversation', '由檢舉人從端對端加密會話中選取、解密並提交', '신고자가 종단간 암호화 대화에서 선택하고 복호화하여 제출함', '通報者がエンドツーエンド暗号化された会話から選択・復号して送信', 'Seleccionado, descifrado y enviado por quien denuncia desde una conversación cifrada de extremo a extremo', 'Sélectionné, déchiffré et envoyé par l’auteur du signalement depuis une conversation chiffrée de bout en bout', 'Vom Meldenden aus einer Ende-zu-Ende-verschlüsselten Unterhaltung ausgewählt, entschlüsselt und eingereicht'],
  ['未加密消息', 'Unencrypted message', '未加密訊息', '암호화되지 않은 메시지', '暗号化されていないメッセージ', 'Mensaje sin cifrar', 'Message non chiffré', 'Unverschlüsselte Nachricht'],
];

const TRANSLATIONS = new Map(ROWS.map((row) => [row[0], {
  en: row[1],
  'zh-CN': row[0],
  'zh-TW': row[2] || row[1],
  ko: row[3] || row[1],
  ja: row[4] || row[1],
  es: row[5] || row[1],
  fr: row[6] || row[1],
  de: row[7] || row[1],
}]));
for (const [language, pack] of Object.entries(MACHINE_TRANSLATIONS)) {
  for (const [source, translated] of Object.entries(pack)) {
    if (translated && TRANSLATIONS.has(source)) TRANSLATIONS.get(source)[language] = translated;
  }
}

let locale = 'en';
let observer;
const originalText = new WeakMap();
const renderedText = new WeakMap();
const originalAttributes = new WeakMap();
const renderedAttributes = new WeakMap();
const TRANSLATED_ATTRIBUTES = ['aria-label', 'title', 'placeholder', 'content'];
const IGNORE_TEXT = '.message-bubble, .conversation-preview, .conversation-item strong, .attachment-card strong, .member-list strong, .member-list code, #users td:first-child, #self-name, #peer-name, #domain-value, code, [data-user-content], [data-i18n-ignore]';

function normalizeLocale(value) {
  return CODES.includes(value) ? value : 'en';
}

export function currentLocale() {
  return locale;
}

function applyTemplate(source, language) {
  const templates = [
    ['connected_to', /^连接到 (.+)$/, { en: 'Connected to $1', 'zh-TW': '連線至 $1', ko: '$1에 연결됨', ja: '$1 に接続', es: 'Conectado a $1', fr: 'Connecté à $1', de: 'Verbunden mit $1' }],
    ['administrator', /^管理员：(.+)$/, { en: 'Administrator: $1', 'zh-TW': '管理員：$1', ko: '관리자: $1', ja: '管理者: $1', es: 'Administrador: $1', fr: 'Administrateur : $1', de: 'Administrator: $1' }],
    ['online_count', /^(\d+) 人在线$/, { en: '$1 online', 'zh-TW': '$1 人在線', ko: '$1명 온라인', ja: '$1人オンライン', es: '$1 en línea', fr: '$1 en ligne', de: '$1 online' }],
    ['group_online_count', /^群聊 · (\d+) 人在线$/, { en: 'Group · $1 online', 'zh-TW': '群聊 · $1 人在線', ko: '그룹 · $1명 온라인', ja: 'グループ · $1人オンライン', es: 'Grupo · $1 en línea', fr: 'Groupe · $1 en ligne', de: 'Gruppe · $1 online' }],
    ['contact_request', /^(.+) 希望添加你为联系人$/, { en: '$1 wants to add you as a contact', 'zh-TW': '$1 希望將你加為聯絡人', ko: '$1 님이 연락처 추가를 요청했습니다', ja: '$1 が連絡先への追加を希望しています', es: '$1 quiere añadirte como contacto', fr: '$1 souhaite vous ajouter comme contact', de: '$1 möchte dich als Kontakt hinzufügen' }],
    ['typing', /^(.+) 正在输入…$/, { en: '$1 is typing…', 'zh-TW': '$1 正在輸入…', ko: '$1 님이 입력 중…', ja: '$1 が入力中…', es: '$1 está escribiendo…', fr: '$1 écrit…', de: '$1 schreibt…' }],
    ['encrypted_devices', /^(\d+) 台加密设备$/, { en: '$1 encrypted devices', 'zh-TW': '$1 台加密裝置', ko: '암호화 장치 $1대', ja: '暗号化端末 $1台', es: '$1 dispositivos cifrados', fr: '$1 appareils chiffrés', de: '$1 verschlüsselte Geräte' }],
    ['receiving_devices', /^已发现 (\d+) 台接收设备；服务器只能保存密文。$/, { en: '$1 receiving devices found; the server can store ciphertext only.', 'zh-TW': '已找到 $1 台接收裝置；伺服器只能儲存密文。', ko: '수신 장치 $1대를 찾았습니다. 서버에는 암호문만 저장됩니다.', ja: '受信端末が$1台見つかりました。サーバーは暗号文のみ保存できます。', es: 'Se encontraron $1 dispositivos receptores; el servidor solo puede guardar texto cifrado.', fr: '$1 appareils destinataires trouvés ; le serveur ne peut conserver que le texte chiffré.', de: '$1 Empfangsgeräte gefunden; der Server kann nur Chiffretext speichern.' }],
    ['device', /^设备 (\d+)$/, { en: 'Device $1', 'zh-TW': '裝置 $1', ko: '장치 $1', ja: '端末 $1', es: 'Dispositivo $1', fr: 'Appareil $1', de: 'Gerät $1' }],
    ['request_failed', /^请求失败 \((\d+)\)$/, { en: 'Request failed ($1)', 'zh-TW': '請求失敗（$1）', ko: '요청 실패 ($1)', ja: 'リクエストに失敗しました ($1)', es: 'La solicitud falló ($1)', fr: 'Échec de la requête ($1)', de: 'Anfrage fehlgeschlagen ($1)' }],
    ['config_failed', /^无法读取服务器配置：(.+)$/, { en: 'Could not read the server configuration: $1', 'zh-TW': '無法讀取伺服器設定：$1', ko: '서버 구성을 읽을 수 없습니다: $1', ja: 'サーバー設定を読み込めませんでした: $1', es: 'No se pudo leer la configuración del servidor: $1', fr: 'Impossible de lire la configuration du serveur : $1', de: 'Serverkonfiguration konnte nicht gelesen werden: $1' }],
    ['complete_address', /^请输入 (.+) 上的完整 XMPP 地址$/, { en: 'Enter a complete XMPP address on $1', 'zh-TW': '請輸入 $1 上的完整 XMPP 位址', ko: '$1의 전체 XMPP 주소를 입력하세요', ja: '$1 の完全な XMPP アドレスを入力してください', es: 'Introduce una dirección XMPP completa en $1', fr: 'Saisissez une adresse XMPP complète sur $1', de: 'Gib eine vollständige XMPP-Adresse auf $1 ein' }],
    ['remove_contact', /^从联系人中移除 (.+)？$/, { en: 'Remove $1 from contacts?', 'zh-TW': '從聯絡人中移除 $1？', ko: '$1 님을 연락처에서 삭제할까요?', ja: '$1 を連絡先から削除しますか？', es: '¿Quitar a $1 de los contactos?', fr: 'Retirer $1 des contacts ?', de: '$1 aus den Kontakten entfernen?' }],
    ['history_failed', /^历史记录读取失败：(.+)$/, { en: 'Could not read history: $1', 'zh-TW': '歷史記錄讀取失敗：$1', ko: '기록을 읽을 수 없습니다: $1', ja: '履歴を読み込めませんでした: $1', es: 'No se pudo leer el historial: $1', fr: 'Impossible de lire l’historique : $1', de: 'Verlauf konnte nicht gelesen werden: $1' }],
    ['decrypt_failed', /^\[无法解密：(.+)\]$/, { en: '[Could not decrypt: $1]', 'zh-TW': '[無法解密：$1]', ko: '[복호화할 수 없음: $1]', ja: '[復号できません: $1]', es: '[No se pudo descifrar: $1]', fr: '[Impossible de déchiffrer : $1]', de: '[Entschlüsselung nicht möglich: $1]' }],
    ['group_topic', /^群主题：(.+)$/, { en: 'Group topic: $1', 'zh-TW': '群組主題：$1', ko: '그룹 주제: $1', ja: 'グループのトピック: $1', es: 'Tema del grupo: $1', fr: 'Sujet du groupe : $1', de: 'Gruppenthema: $1' }],
    ['message_devices_failed', /^(\d+) 个其他设备未收到消息$/, { en: '$1 other devices did not receive the message', 'zh-TW': '$1 台其他裝置未收到訊息', ko: '다른 장치 $1대가 메시지를 받지 못했습니다', ja: '他の端末$1台がメッセージを受信しませんでした', es: '$1 dispositivos más no recibieron el mensaje', fr: '$1 autres appareils n’ont pas reçu le message', de: '$1 weitere Geräte haben die Nachricht nicht erhalten' }],
    ['message_failed', /^消息没有发送：(.+)$/, { en: 'Message not sent: $1', 'zh-TW': '訊息未傳送：$1', ko: '메시지를 보내지 못했습니다: $1', ja: 'メッセージを送信できませんでした: $1', es: 'Mensaje no enviado: $1', fr: 'Message non envoyé : $1', de: 'Nachricht nicht gesendet: $1' }],
    ['file_limit', /^文件不能超过 (.+)$/, { en: 'The file cannot exceed $1', 'zh-TW': '檔案不能超過 $1', ko: '파일은 $1를 초과할 수 없습니다', ja: 'ファイルは $1 以下にしてください', es: 'El archivo no puede superar $1', fr: 'Le fichier ne peut pas dépasser $1', de: 'Die Datei darf $1 nicht überschreiten' }],
    ['upload_failed', /^加密文件上传失败 \((\d+)\)$/, { en: 'Encrypted file upload failed ($1)', 'zh-TW': '加密檔案上傳失敗（$1）', ko: '암호화 파일 업로드 실패 ($1)', ja: '暗号化ファイルのアップロードに失敗しました ($1)', es: 'Error al subir el archivo cifrado ($1)', fr: 'Échec de l’envoi du fichier chiffré ($1)', de: 'Upload der verschlüsselten Datei fehlgeschlagen ($1)' }],
    ['file_key_devices_failed', /^(\d+) 个设备未收到文件密钥$/, { en: '$1 devices did not receive the file key', 'zh-TW': '$1 台裝置未收到檔案金鑰', ko: '장치 $1대가 파일 키를 받지 못했습니다', ja: '端末$1台がファイル鍵を受信しませんでした', es: '$1 dispositivos no recibieron la clave del archivo', fr: '$1 appareils n’ont pas reçu la clé du fichier', de: '$1 Geräte haben den Dateischlüssel nicht erhalten' }],
    ['file_failed', /^文件没有发送：(.+)$/, { en: 'File not sent: $1', 'zh-TW': '檔案未傳送：$1', ko: '파일을 보내지 못했습니다: $1', ja: 'ファイルを送信できませんでした: $1', es: 'Archivo no enviado: $1', fr: 'Fichier non envoyé : $1', de: 'Datei nicht gesendet: $1' }],
    ['download_failed', /^文件下载失败 \((\d+)\)$/, { en: 'File download failed ($1)', 'zh-TW': '檔案下載失敗（$1）', ko: '파일 다운로드 실패 ($1)', ja: 'ファイルのダウンロードに失敗しました ($1)', es: 'Error al descargar el archivo ($1)', fr: 'Échec du téléchargement du fichier ($1)', de: 'Dateidownload fehlgeschlagen ($1)' }],
    ['device_label', /^(.+) · 设备 (\d+)$/, { en: '$1 · Device $2', 'zh-TW': '$1 · 裝置 $2', ko: '$1 · 장치 $2', ja: '$1 · 端末 $2', es: '$1 · Dispositivo $2', fr: '$1 · Appareil $2', de: '$1 · Gerät $2' }],
    ['bundle_incomplete', /^设备 (\d+) 的 OMEMO 公钥包不完整$/, { en: 'The OMEMO public-key bundle for device $1 is incomplete', 'zh-TW': '裝置 $1 的 OMEMO 公開金鑰套件不完整', ko: '장치 $1의 OMEMO 공개 키 번들이 불완전합니다', ja: '端末 $1 の OMEMO 公開鍵バンドルが不完全です', es: 'El paquete de clave pública OMEMO del dispositivo $1 está incompleto', fr: 'Le paquet de clé publique OMEMO de l’appareil $1 est incomplet', de: 'Das OMEMO-Public-Key-Bundle für Gerät $1 ist unvollständig' }],
  ];
  for (const [id, pattern, values] of templates) {
    const replacement = values[language] || MACHINE_TEMPLATES[language]?.[id] || values.en;
    if (pattern.test(source)) return source.replace(pattern, replacement);
  }
  return null;
}

export function translate(source, language = locale) {
  if (typeof source !== 'string' || !source) return source;
  const languageCode = normalizeLocale(language);
  const leading = source.match(/^\s*/)?.[0] || '';
  const trailing = source.match(/\s*$/)?.[0] || '';
  const core = source.slice(leading.length, source.length - trailing.length);
  if (!core) return source;
  const row = TRANSLATIONS.get(core);
  const translated = row?.[languageCode] || row?.en || applyTemplate(core, languageCode);
  return translated ? `${leading}${translated}${trailing}` : source;
}

function shouldIgnoreText(node) {
  return node.parentElement?.closest(IGNORE_TEXT);
}

function translateTextNode(node) {
  if (shouldIgnoreText(node)) return;
  const current = node.nodeValue || '';
  if (current !== renderedText.get(node)) originalText.set(node, current);
  const source = originalText.get(node) ?? current;
  const target = translate(source);
  renderedText.set(node, target);
  if (current !== target) node.nodeValue = target;
}

function attributeState(store, element) {
  let values = store.get(element);
  if (!values) {
    values = new Map();
    store.set(element, values);
  }
  return values;
}

function translateAttribute(element, name) {
  if (!element.hasAttribute(name) || element.matches('[data-i18n-ignore]')) return;
  const current = element.getAttribute(name) || '';
  const originals = attributeState(originalAttributes, element);
  const rendered = attributeState(renderedAttributes, element);
  if (current !== rendered.get(name)) originals.set(name, current);
  const target = translate(originals.get(name) ?? current);
  rendered.set(name, target);
  if (current !== target) element.setAttribute(name, target);
}

function translateElement(element) {
  for (const name of TRANSLATED_ATTRIBUTES) translateAttribute(element, name);
}

function translateTree(root = document) {
  if (root.nodeType === Node.TEXT_NODE) translateTextNode(root);
  if (root.nodeType === Node.ELEMENT_NODE) translateElement(root);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (node.nodeType === Node.TEXT_NODE) translateTextNode(node);
    else translateElement(node);
  }
}

function installPicker() {
  if (document.querySelector('[data-language-picker]')) return;
  let hosts = [...document.querySelectorAll('[data-language-host]')];
  if (!hosts.length) hosts = [document.body];
  for (const host of hosts) host.append(createPicker());
}

function installMachineTranslationNotice() {
  if (document.querySelector('[data-machine-translation-notice]')) return;
  const notice = document.createElement('aside');
  notice.className = 'machine-translation-notice hidden';
  notice.dataset.machineTranslationNotice = '';
  notice.setAttribute('role', 'status');
  const icon = document.createElement('span');
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = '⚠';
  const message = document.createElement('span');
  message.textContent = '机器翻译，可能存在错误';
  notice.append(icon, message);
  document.body.append(notice);
  updateMachineTranslationNotice();
}

function updateMachineTranslationNotice() {
  const notice = document.querySelector('[data-machine-translation-notice]');
  if (!notice) return;
  notice.classList.toggle('hidden', HUMAN_TRANSLATED_CODES.has(locale));
}

function normalizedSearch(value) {
  return value.trim().normalize('NFKD').toLocaleLowerCase('en');
}

function languageMatches(language, query) {
  return !query || language.searchText.includes(query);
}

export function searchLanguages(value) {
  const query = normalizedSearch(value);
  return LANGUAGES.filter((language) => languageMatches(language, query));
}

function languageOption(language, picker, closePicker) {
  const option = document.createElement('button');
  option.type = 'button';
  option.className = 'language-option';
  option.dataset.languageCode = language.code;
  option.dataset.i18nIgnore = '';
  option.setAttribute('role', 'option');
  option.setAttribute('lang', language.code);
  option.textContent = language.label;
  option.addEventListener('click', () => {
    setLanguage(language.code);
    closePicker();
  });
  picker.options.push(option);
  return option;
}

function createLanguageSection(title, languages, picker, closePicker) {
  const section = document.createElement('section');
  section.className = 'language-section';
  const heading = document.createElement('h3');
  heading.textContent = title;
  const list = document.createElement('div');
  list.className = 'language-options';
  list.setAttribute('role', 'listbox');
  for (const language of languages) list.append(languageOption(language, picker, closePicker));
  section.append(heading, list);
  return { section, list };
}

function createPicker() {
  const wrapper = document.createElement('div');
  wrapper.className = 'language-picker';
  wrapper.dataset.languagePicker = '';
  const picker = { wrapper, options: [] };
  const caption = document.createElement('span');
  caption.className = 'language-caption';
  caption.textContent = '语言';

  const trigger = document.createElement('button');
  trigger.type = 'button';
  trigger.className = 'language-trigger';
  trigger.setAttribute('aria-label', '语言');
  trigger.setAttribute('aria-haspopup', 'dialog');
  trigger.setAttribute('aria-expanded', 'false');
  const current = document.createElement('span');
  current.className = 'language-current';
  current.dataset.i18nIgnore = '';
  const chevron = document.createElement('span');
  chevron.className = 'language-chevron';
  chevron.setAttribute('aria-hidden', 'true');
  chevron.textContent = '▾';
  trigger.append(current, chevron);

  const panel = document.createElement('div');
  panel.className = 'language-panel hidden';
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', '语言');

  const searchRow = document.createElement('div');
  searchRow.className = 'language-search';
  const input = document.createElement('input');
  input.type = 'search';
  input.autocomplete = 'off';
  input.spellcheck = false;
  input.placeholder = '搜索语言';
  input.setAttribute('aria-label', '搜索语言');
  const clear = document.createElement('button');
  clear.type = 'button';
  clear.className = 'language-search-action clear';
  clear.setAttribute('aria-label', '清除搜索');
  clear.title = '清除搜索';
  clear.textContent = '×';
  const search = document.createElement('button');
  search.type = 'button';
  search.className = 'language-search-action submit';
  search.setAttribute('aria-label', '执行搜索');
  search.title = '执行搜索';
  search.textContent = '🔍';
  searchRow.append(input, clear, search);

  const closePicker = () => {
    panel.classList.add('hidden');
    trigger.setAttribute('aria-expanded', 'false');
  };
  const recommended = createLanguageSection('推荐', RECOMMENDED_LANGUAGES, picker, closePicker);
  const remaining = createLanguageSection(
    '所有语言',
    LANGUAGES.filter(({ recommended: isRecommended }) => !isRecommended),
    picker,
    closePicker,
  );
  const empty = document.createElement('p');
  empty.className = 'language-empty hidden';
  empty.textContent = '没有符合条件的语言';
  panel.append(searchRow, recommended.section, remaining.section, empty);

  const renderResults = () => {
    const query = normalizedSearch(input.value);
    const matchingCodes = new Set(searchLanguages(query).map(({ code }) => code));
    let matches = 0;
    for (const option of picker.options) {
      const visible = matchingCodes.has(option.dataset.languageCode);
      option.classList.toggle('hidden', !visible);
      if (visible) matches += 1;
    }
    recommended.section.classList.toggle('hidden', ![...recommended.list.children].some((option) => !option.classList.contains('hidden')));
    remaining.section.classList.toggle('hidden', ![...remaining.list.children].some((option) => !option.classList.contains('hidden')));
    empty.classList.toggle('hidden', matches !== 0);
    clear.classList.toggle('is-empty', !query);
  };

  input.addEventListener('input', renderResults);
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      renderResults();
    }
    if (event.key === 'Escape') closePicker();
  });
  clear.addEventListener('click', () => {
    input.value = '';
    renderResults();
    input.focus();
  });
  search.addEventListener('click', () => {
    renderResults();
    input.focus();
  });
  trigger.addEventListener('click', () => {
    const opening = panel.classList.contains('hidden');
    for (const other of document.querySelectorAll('[data-language-picker] .language-panel')) {
      other.classList.add('hidden');
      other.closest('[data-language-picker]')?.querySelector('.language-trigger')?.setAttribute('aria-expanded', 'false');
    }
    panel.classList.toggle('hidden', !opening);
    trigger.setAttribute('aria-expanded', String(opening));
    if (opening) {
      renderResults();
      requestAnimationFrame(() => input.focus());
    }
  });
  document.addEventListener('pointerdown', (event) => {
    if (!wrapper.contains(event.target)) closePicker();
  });

  wrapper.append(caption, trigger, panel);
  picker.current = current;
  wrapper._languagePicker = picker;
  updatePicker(picker);
  return wrapper;
}

function updatePicker(picker) {
  const selected = LANGUAGE_BY_CODE.get(locale) || LANGUAGE_BY_CODE.get('en');
  picker.current.textContent = selected.label;
  for (const option of picker.options) {
    const active = option.dataset.languageCode === selected.code;
    option.classList.toggle('active', active);
    option.setAttribute('aria-selected', String(active));
  }
}

export function setLanguage(value) {
  locale = normalizeLocale(value);
  localStorage.setItem(STORAGE_KEY, locale);
  document.documentElement.lang = locale;
  for (const wrapper of document.querySelectorAll('[data-language-picker]')) {
    if (wrapper._languagePicker) updatePicker(wrapper._languagePicker);
  }
  translateTree(document);
  updateMachineTranslationNotice();
  window.dispatchEvent(new CustomEvent('northstar:languagechange', { detail: { language: locale } }));
}

export function initializeI18n() {
  locale = normalizeLocale(localStorage.getItem(STORAGE_KEY) || 'en');
  document.documentElement.lang = locale;
  installPicker();
  installMachineTranslationNotice();
  translateTree(document);
  observer?.disconnect();
  observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === 'characterData') translateTextNode(mutation.target);
      if (mutation.type === 'attributes') translateAttribute(mutation.target, mutation.attributeName);
      for (const node of mutation.addedNodes) translateTree(node);
    }
  });
  observer.observe(document.documentElement, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: TRANSLATED_ATTRIBUTES,
  });
  return locale;
}
