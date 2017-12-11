<?php

namespace Drupal\auth0\Controller;

use Drupal\Core\Controller\ControllerBase;
use GuzzleHttp\Client;
use Drupal\Core\Url;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\PageCache\ResponsePolicyInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Auth0\Auth0Helper;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;

use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

use Drupal\auth0\Event\Auth0UserSigninEvent;
use Drupal\auth0\Event\Auth0UserSignupEvent;

use Drupal\auth0\Exception\EmailNotSetException;
use Drupal\auth0\Exception\EmailNotVerifiedException;

use Auth0\SDK\JWTVerifier;
use Firebase\JWT\JWT;
use Auth0\SDK\Auth0;
use Auth0\SDK\API\Authentication;
use Auth0\SDK\API\Management;

/**
 * Controller routines for auth0 authentication.
 */
class AuthController extends ControllerBase {

  /**
   * The event dispatcher.
   *
   * @var \Symfony\Component\EventDispatcher\EventDispatcherInterface
   */
  protected $eventDispatcher;

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $config;

  /**
   * Logs messages and errors.
   *
   * @var \Drupal\Core\Logger\LoggerChannelInterface
   */
  protected $logger;

  /**
   * The auth0 instance.
   *
   * @var \Auth0\SDK\Auth0
   */
  protected $auth0 = FALSE;

  /**
   * The auth0 helper.
   *
   * @var \Drupal\Auth0\Auth0Helper
   */
  protected $helper;

  /**
   * The http client.
   *
   * @var \Drupal\auth0\Controller\ClientFactory
   */
  protected $httpClient;

  /**
   * If to redirect for SSO.
   *
   * @var bool
   */
  protected $redirectForSso;

  /**
   * AuthController constructor.
   *
   * @param \Drupal\Core\PageCache\ResponsePolicyInterface $page_kill_switch
   *   Determine's if page should be stored in cache.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config
   *   The config factory.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger
   *   The logger to log messages and errors.
   * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $event_dispatcher
   *   Dispatches events.
   * @param \GuzzleHttp\Client $http_client
   *   The http client to make external requests.
   * @param \Drupal\Auth0\Auth0Helper $helper
   *   The auth0 helper.
   */
  public function __construct(
    ResponsePolicyInterface $page_kill_switch,
    ConfigFactoryInterface $config,
    LoggerChannelFactoryInterface $logger,
    EventDispatcherInterface $event_dispatcher,
    Client $http_client,
    Auth0Helper $helper
  ) {
    // Ensure the pages this controller servers never gets cached.
    $page_kill_switch->trigger();

    $this->eventDispatcher = $event_dispatcher;

    $this->logger = $logger->get('auth0');
    $this->config = $config->get('auth0.settings');
    $this->httpClient = $http_client;
    $this->helper = $helper;
    $this->redirectForSso = (bool) $this->config->get('auth0_redirect_for_sso');
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('page_cache_kill_switch'),
      $container->get('config.factory'),
      $container->get('logger.factory'),
      $container->get('event_dispatcher'),
      $container->get('http_client'),
      $container->get('auth0.helper')
    );
  }

  /**
   * Login method.
   *
   * @return array|\Drupal\Core\Routing\TrustedRedirectResponse
   *   The redirect response.
   */
  public function login() {
    global $base_root;

    // If supporting SSO, redirect to the hosted login page for authorization.
    if ($this->redirectForSso) {
      return new TrustedRedirectResponse($this->buildAuthorizeUrl('none'));
    }

    $lockExtraSettings = $this->config->get('auth0_lock_extra_settings');
    $lockExtraSettings = empty($lockExtraSettings) ? NULL : $lockExtraSettings;

    // Not doing SSO, so show login page.
    return [
      '#theme' => 'auth0_login',
      '#loginCSS' => $this->config->get('auth0_login_css'),
      '#attached' => [
        'library' => [
          'auth0/auth0.lock',
        ],
        'drupalSettings' => [
          'auth0' => [
            'clientId' => $this->config->get(Auth0Helper::AUTH0_CLIENT_ID),
            'domain' => $this->config->get(Auth0Helper::AUTH0_DOMAIN),
            'lockOptions' => $lockExtraSettings,
            'showSignup' => $this->config->get('auth0_allow_signup'),
            'callbackURL' => "$base_root/auth0/callback",
            'state' => $this->helper->getNonce(),
          ],
        ],
      ],
    ];
  }

  /**
   * Logout method.
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse
   *   The redirect.
   */
  public function logout() {
    global $base_root;

    $auth0Api = new Authentication($this->config->get(Auth0Helper::AUTH0_DOMAIN), $this->config->get(Auth0Helper::AUTH0_CLIENT_ID));

    user_logout();

    // If we are using SSO, we need to logout completely from Auth0, otherwise
    // they will just logout of their client.
    $link = $auth0Api->get_logout_link(
      $base_root,
      $this->redirectForSso ? NULL : $this->config->get(Auth0Helper::AUTH0_CLIENT_ID)
    );

    return new TrustedRedirectResponse($link);
  }

  /**
   * Build the Authorize url.
   *
   * @param string $prompt
   *   The prompt.
   *
   * @return mixed
   *   The authorize url.
   */
  protected function buildAuthorizeUrl($prompt) {
    global $base_root;

    $auth0Api = new Authentication(
      $this->config->get(Auth0Helper::AUTH0_DOMAIN),
      $this->config->get(Auth0Helper::AUTH0_CLIENT_ID)
    );

    $response_type = 'code';
    $redirect_uri = "$base_root/auth0/callback";
    $connection = NULL;
    $state = $this->helper->getNonce();
    $additional_params = [];
    $additional_params['scope'] = 'openid profile email';

    if ($prompt) {
      $additional_params['prompt'] = $prompt;
    }

    return $auth0Api->get_authorize_link($response_type, $redirect_uri, $connection, $state, $additional_params);
  }

  /**
   * Handles the callback for the oauth transaction.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   The redirect response.
   */
  public function callback(Request $request) {
    global $base_root;

    // Check in query.
    if ($request->get('error') == 'login_required') {
      return new TrustedRedirectResponse($this->buildAuthorizeUrl(FALSE));
    }

    // Set store to null so that the store is set to SessionStore.
    $this->auth0 = new Auth0([
      'domain'        => $this->config->get(Auth0Helper::AUTH0_DOMAIN),
      'client_id'     => $this->config->get(Auth0Helper::AUTH0_CLIENT_ID),
      'client_secret' => $this->config->get(Auth0Helper::AUTH0_CLIENT_SECRET),
      'redirect_uri'  => "$base_root/auth0/callback",
      'store' => NULL,
      'persist_id_token' => FALSE,
      'persist_user' => FALSE,
      'persist_access_token' => FALSE,
      'persist_refresh_token' => FALSE,
    ]);

    $userInfo = NULL;

    // Exchange the code for the tokens (happens behind the scenes in the SDK).
    try {
      $userInfo = $this->auth0->getUser();
      $idToken = $this->auth0->getIdToken();
    }
    catch (\Exception $e) {
      return $this->failLogin(t('There was a problem logging you in, sorry for the inconvenience.'),
        'Failed to exchange code for tokens: ' . $e->getMessage());
    }

    // Validate the ID Token.
    $auth0_domain = 'https://' . $this->config->get(Auth0Helper::AUTH0_DOMAIN) . '/';
    $auth0_settings = [];
    $auth0_settings['authorized_iss'] = [$auth0_domain];
    $auth0_settings['supported_algs'] = [$this->config->get(Auth0Helper::AUTH0_JWT_SIGNING_ALGORITHM)];
    $auth0_settings['valid_audiences'] = [$this->config->get(Auth0Helper::AUTH0_CLIENT_ID)];
    $auth0_settings['client_secret'] = $this->config->get(Auth0Helper::AUTH0_CLIENT_SECRET);
    $auth0_settings['secret_base64_encoded'] = $this->config->get(Auth0Helper::AUTH0_SECRET_ENCODED);
    $jwt_verifier = new JWTVerifier($auth0_settings);
    try {
      JWT::$leeway = $this->config->get('auth0_jwt_leeway') ?: AUTH0_JWT_LEEWAY_DEFAULT;
      $user = $jwt_verifier->verifyAndDecode($idToken);
    }
    catch (\Exception $e) {
      return $this->failLogin(t('There was a problem logging you in, sorry for the inconvenience.'),
        'Failed to verify and decode the JWT: ' . $e->getMessage());
    }

    // Validate the state if we redirected for login.
    $state = $request->get('state', 'invalid');

    if (!$this->helper->compareNonce($state)) {
      return $this->failLogin(t('There was a problem logging you in, sorry for the inconvenience.'),
        "Failed to verify the state ($state)");
    }

    // Check the sub if it exists
    // (this will exist if you have enabled OIDC Conformant).
    if ($userInfo['sub'] != $user->sub) {
      return $this->failLogin(t('There was a problem logging you in, sorry for the inconvenience.'),
        'Failed to verify the JWT sub.');
    }
    elseif (array_key_exists('sub', $userInfo)) {
      $userInfo['user_id'] = $userInfo['sub'];
    }

    if ($userInfo) {
      return $this->processUserLogin($request, $userInfo, $idToken);
    }

    return $this->failLogin(t('There was a problem logging you in, sorry for the inconvenience.'),
      'No userInfo found');
  }

  /**
   * Checks if the email is valid.
   *
   * @param array $userInfo
   *   The auth0 user info.
   *
   * @throws \Drupal\auth0\Exception\EmailNotSetException
   *   Throws email not set exception.
   *
   * @throws \Drupal\auth0\Exception\EmailNotVerifiedException
   *   Throws email not verified exception.
   */
  protected function validateUserEmail(array $userInfo) {
    $requires_email = $this->config->get('auth0_requires_verified_email');

    if ($requires_email) {
      if (!isset($userInfo['email']) || empty($userInfo['email'])) {
        throw new EmailNotSetException();
      }
      if (!$userInfo['email_verified']) {
        throw new EmailNotVerifiedException();
      }
    }
  }

  /**
   * Process the auth0 user profile and signin or signup the user.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   * @param array $userInfo
   *   The auth0 user info.
   * @param string $idToken
   *   The id token.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   The redirect response.
   */
  protected function processUserLogin(Request $request, array $userInfo, $idToken) {
    try {
      $this->validateUserEmail($userInfo);
    }
    catch (EmailNotSetException $e) {
      return $this->failLogin(t('This account does not have an email associated. Please login with a different provider.'),
        'No Email Found');
    }
    catch (EmailNotVerifiedException $e) {
      return $this->auth0FailWithVerifyEmail($idToken);
    }

    // See if there is a user in the auth0_user table with the user info
    // client id.
    $user = $this->helper->findAuth0User($userInfo['user_id']);

    if ($user) {
      // User exists!
      // update the auth0_user with the new userInfo object.
      $this->helper->updateAuth0User($userInfo);

      $event = new Auth0UserSigninEvent($user, $userInfo);
      $this->eventDispatcher->dispatch(Auth0UserSigninEvent::NAME, $event);
    }
    else {
      try {
        $user = $this->signupUser($userInfo, $idToken);
      }
      catch (EmailNotVerifiedException $e) {
        return $this->auth0FailWithVerifyEmail($idToken);
      }

      $this->helper->insertAuth0User($userInfo, $user->id());

      $event = new Auth0UserSignupEvent($user, $userInfo);
      $this->eventDispatcher->dispatch(Auth0UserSignupEvent::NAME, $event);
    }

    user_login_finalize($user);

    if ($request->request->has('destination')) {
      return $this->redirect($request->request->get('destination'));
    }

    return $this->redirect('entity.user.canonical', ['user' => $user->id()]);
  }

  /**
   * If the user fails to login.
   *
   * @param string $message
   *   The message to display.
   * @param string $logMessage
   *   The message to log.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   The redirect.
   */
  protected function failLogin($message, $logMessage) {
    $this->logger->error($logMessage);
    drupal_set_message($message, 'error');
    if ($this->auth0) {
      $this->auth0->logout();
    }
    return new RedirectResponse('/');
  }

  /**
   * Create or link a new user based on the auth0 profile.
   *
   * @param array $userInfo
   *   The auth0 user info.
   * @param string $idToken
   *   The token.
   *
   * @return bool|\Drupal\Core\Entity\EntityInterface|static
   *   The user.
   *
   * @throws \Drupal\auth0\Exception\EmailNotVerifiedException
   *   Throws email not verified exception.
   */
  protected function signupUser(array $userInfo, $idToken) {
    // If the user doesn't exist we need to either create a new one, or assign
    // him to an existing one.
    $isDatabaseUser = FALSE;

    // Make sure we have the identities array, if not, fetch it from the
    // user endpoint.
    $hasIdentities = (is_object($userInfo) && $userInfo->has('identities')) ||
      (is_array($userInfo) && array_key_exists('identities', $userInfo));
    if (!$hasIdentities) {
      $mgmtClient = new Management($idToken, $this->config->get(Auth0Helper::AUTH0_DOMAIN));

      $user = $mgmtClient->users->get($userInfo['user_id']);
      $userInfo['identities'] = $user['identities'];
    }

    foreach ($userInfo['identities'] as $identity) {
      if ($identity['provider'] == "auth0") {
        $isDatabaseUser = TRUE;
      }
    }
    $joinUser = FALSE;

    // If the user has a verified email or is a database user try to see if
    // there is a user to join with. The isDatabase is because we don't want to
    // allow database user creation if there is an existing one with no
    // verified email.
    if ($userInfo['email_verified'] || $isDatabaseUser) {
      $joinUser = user_load_by_mail($userInfo['email']);
    }

    if ($joinUser) {
      // If we are here, we have a potential join user.
      // Don't allow creation or assignation of user if the email is not
      // verified, that would be hijacking.
      if (!$userInfo['email_verified']) {
        throw new EmailNotVerifiedException();
      }
      $user = $joinUser;
    }
    else {
      // If we are here, we need to create the user.
      $user = $this->helper->createDrupalUser($userInfo);
    }

    return $user;
  }

  /**
   * Email not verified error message.
   *
   * @param string $idToken
   *   The token.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   The redirect response.
   */
  protected function auth0FailWithVerifyEmail($idToken) {

    $url = Url::fromRoute('auth0.verify_email');
    $formText = "<form style='display:none' name='auth0VerifyEmail' action=@url method='post'><input type='hidden' value=@token name='idToken'/></form>";
    $linkText = "<a href='javascript:null' onClick='document.forms[\"auth0VerifyEmail\"].submit();'>here</a>";

    return $this->failLogin(
      t($formText . "Please verify your email and log in again. Click $linkText to Resend verification email.",
        [
          '@url' => $url->toString(),
          '@token' => $idToken,
        ]
    ), 'Email not verified');
  }

  /**
   * Send the verification email.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   The response.
   */
  public function verifyEmail(Request $request) {
    /** @var \Drupal\Core\Config\ImmutableConfig $config */
    $config = $this->config;

    $idToken = $request->get('idToken');

    // Validate the ID Token.
    $auth0_domain = 'https://' . $this->config->get(Auth0Helper::AUTH0_DOMAIN) . '/';
    $auth0_settings = [];
    $auth0_settings['authorized_iss'] = [$auth0_domain];
    $auth0_settings['supported_algs'] = [$this->config->get(Auth0Helper::AUTH0_JWT_SIGNING_ALGORITHM)];
    $auth0_settings['valid_audiences'] = [$this->config->get(Auth0Helper::AUTH0_CLIENT_ID)];
    $auth0_settings['client_secret'] = $this->config->get(Auth0Helper::AUTH0_CLIENT_SECRET);
    $auth0_settings['secret_base64_encoded'] = $this->config->get(Auth0Helper::AUTH0_SECRET_ENCODED);
    $jwt_verifier = new JWTVerifier($auth0_settings);
    try {
      JWT::$leeway = $config->get('auth0_jwt_leeway') ?: AUTH0_JWT_LEEWAY_DEFAULT;
      $user = $jwt_verifier->verifyAndDecode($idToken);
    }
    catch (\Exception $e) {
      return $this->failLogin(t('There was a problem resending the verification email, sorry for the inconvenience.'),
        "Failed to verify and decode the JWT ($idToken) for the verify email page: " . $e->getMessage());
    }

    try {
      $userId = $user->sub;
      $url = $auth0_domain. "api/users/$userId/send_verification_email";

      $this->httpClient->request('POST', $url,
        [
          "headers" => [
            "Authorization" => "Bearer $idToken",
          ],
        ]
      );

      drupal_set_message(t('An Authorization email was sent to your account'));
    }
    catch (\UnexpectedValueException $e) {
      drupal_set_message(t('Your session has expired.'), 'error');
    }
    catch (\Exception $e) {
      drupal_set_message(t('Sorry, we couldnt send the email'), 'error');
    }

    return new RedirectResponse('/');
  }

}
