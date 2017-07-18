<?php

namespace Drupal\auth0\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\user\Entity\User;
use Drupal\user\PrivateTempStoreFactory;
use Drupal\Core\Session\SessionManagerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;

use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

use Drupal\auth0\Event\Auth0UserSigninEvent;
use Drupal\auth0\Event\Auth0UserSignupEvent;

use Drupal\auth0\Exception\EmailNotSetException;
use Drupal\auth0\Exception\EmailNotVerifiedException;

use Auth0\SDK\JWTVerifier;
use Auth0\SDK\Auth0;
use Auth0\SDK\API\Authentication;
use Auth0\SDK\API\Management;

use RandomLib\Factory;

/**
 * Controller routines for auth0 authentication.
 */
class AuthController extends ControllerBase {
  const SESSION = 'auth0';
  const NONCE = 'nonce';
  const AUTH0_LOGGER = 'auth0_controller';
  const AUTH0_DOMAIN = 'auth0_domain';
  const AUTH0_CLIENT_ID = 'auth0_client_id';
  const AUTH0_CLIENT_SECRET = 'auth0_client_secret';
  const AUTH0_REDIRECT_FOR_SSO = 'auth0_redirect_for_sso';
  const AUTH0_JWT_SIGNING_ALGORITHM = 'auth0_jwt_signature_alg';
  const AUTH0_SECRET_ENCODED = 'auth0_secret_base64_encoded';

  protected $eventDispatcher;

  /**
   * Inicialize the controller.
   */
  public function __construct(PrivateTempStoreFactory $tempStoreFactory, SessionManagerInterface $sessionManager) {
    // Ensure the pages this controller servers never gets cached
    \Drupal::service('page_cache_kill_switch')->trigger();

    $this->eventDispatcher = \Drupal::service('event_dispatcher');
    $this->tempStore = $tempStoreFactory->get(AuthController::SESSION);
    $this->sessionManager = $sessionManager;
    $this->logger = \Drupal::logger(AuthController::AUTH0_LOGGER);
    $this->config = \Drupal::service('config.factory')->get('auth0.settings');
    $this->domain = $this->config->get(AuthController::AUTH0_DOMAIN);
    $this->client_id = $this->config->get(AuthController::AUTH0_CLIENT_ID);
    $this->client_secret = $this->config->get(AuthController::AUTH0_CLIENT_SECRET);
    $this->redirect_for_sso = $this->config->get(AuthController::AUTH0_REDIRECT_FOR_SSO);
    $this->auth0_jwt_signature_alg = $this->config->get(AuthController::AUTH0_JWT_SIGNING_ALGORITHM);
    $this->secret_base64_encoded = FALSE || $this->config->get(AuthController::AUTH0_SECRET_ENCODED);
    $this->auth0 = FALSE;
  }

  public static function create(ContainerInterface $container) {
    return new static(
        $container->get('user.private_tempstore'),
        $container->get('session_manager')
    );
  }

  /**
   * Handles the login page override.
   */
  public function login() {
    global $base_root;

    $config = \Drupal::service('config.factory')->get('auth0.settings');

    $lockExtraSettings = $config->get('auth0_lock_extra_settings');

    if (trim($lockExtraSettings) == "") {
      $lockExtraSettings = "{}";
    }

    /** 
     * If supporting SSO, redirect to the hosted login page for authorization 
     */
    if ($this->redirect_for_sso == TRUE) {
      $prompt = 'none';
      return new TrustedRedirectResponse($this->buildAuthorizeUrl($prompt));
    }

    /* Not doing SSO, so show login page */
    return array(
      '#theme' => 'auth0_login',
      '#domain' => $config->get('auth0_domain'),
      '#clientID' => $config->get('auth0_client_id'),
      '#state' => $this->getNonce(),
      '#showSignup' => $config->get('auth0_allow_signup'),
      '#widgetCdn' => $config->get('auth0_widget_cdn'),
      '#loginCSS' => $config->get('auth0_login_css'),
      '#lockExtraSettings' => $lockExtraSettings,
      '#callbackURL' => "$base_root/auth0/callback",
    );
  }

  /**
   * Handles the login page override.
   */
  public function logout() {
    global $base_root;

    $auth0Api = new Authentication($this->domain, $this->client_id);

    user_logout();
    
    // if we are using SSO, we need to logout completely from Auth0, otherwise they will just logout of their client
    return new TrustedRedirectResponse($auth0Api->get_logout_link($base_root, $this->redirect_for_sso ? null : $this->client_id));
  }

  /**
   * Create a new nonce in session and return it
   */
  protected function getNonce() {
    // Have to start the session after putting something into the session, or we don't actually start it!
    if (!$this->sessionManager->isStarted() && !isset($_SESSION['auth0_is_session_started'])) {
      $_SESSION['auth0_is_session_started'] = 'yes';
      $this->sessionManager->start();
    }

    $factory = new Factory;
    $generator = $factory->getMediumStrengthGenerator();
    $nonces = $this->tempStore->get(AuthController::NONCE);
    if (!is_array($nonces)) $nonces = array();
    $nonce = base64_encode($generator->generate(32));
    $newNonceArray = array_merge($nonces, [$nonce]);
    $this->tempStore->set(AuthController::NONCE, $newNonceArray);

    return $nonce;
  }

  /**
   * Do our one-time check against the nonce stored in session
   */
  protected function compareNonce($nonce) {
    $nonces = $this->tempStore->get(AuthController::NONCE);
    if (!is_array($nonces)) {
      $this->logger->error("Couldn't verify state because there was no nonce in storage");
      return FALSE;
    }
    $index = array_search($nonce,$nonces);
    if ($index !== FALSE) {
      unset($nonces[$index]);
      $this->tempStore->set(AuthController::NONCE, $nonces);
      return TRUE;
    }

    $this->logger->error("$nonce not found in: ".implode(',', $nonces));
    return FALSE;
  }

  /**
   * Build the Authorize url
   * @param $prompt none|login if prompt=none should be passed, false if not
   */
  protected function buildAuthorizeUrl($prompt) {
    global $base_root;

    $auth0Api = new Authentication($this->domain, $this->client_id);

    $response_type = 'code';
    $redirect_uri = "$base_root/auth0/callback";
    $connection = null;
    $state = $this->getNonce();
    $additional_params = [];
    $additional_params['scope'] = 'openid profile email';
    if ($prompt) $additional_params['prompt'] = $prompt;

    return $auth0Api->get_authorize_link($response_type, $redirect_uri, $connection, $state, $additional_params);
  }

  /**
   * Handles the callback for the oauth transaction.
   */
  public function callback(Request $request) {
    global $base_root;

    $config = \Drupal::service('config.factory')->get('auth0.settings');

    /* Check for errors */
    // Check in query
    if ($request->query->has('error') && $request->query->get('error') == 'login_required') {
      return new TrustedRedirectResponse($this->buildAuthorizeUrl(FALSE));
    }
    // Check in post
    if ($request->request->has('error') && $request->request->get('error') == 'login_required') {
      return new TrustedRedirectResponse($this->buildAuthorizeUrl(FALSE));
    }

    $this->auth0 = new Auth0(array(
        'domain'        => $config->get('auth0_domain'),
        'client_id'     => $config->get('auth0_client_id'),
        'client_secret' => $config->get('auth0_client_secret'),
        'redirect_uri'  => "$base_root/auth0/callback",
        'store' => NULL, // Set to null so that the store is set to SessionStore.
        'persist_id_token' => FALSE,
        'persist_user' => FALSE,
        'persist_access_token' => FALSE,
        'persist_refresh_token' => FALSE    
        ));

    $userInfo = NULL;

    /**
     * Exchange the code for the tokens (happens behind the scenes in the SDK)
     */
    try {
      $userInfo = $this->auth0->getUser();
      $idToken = $this->auth0->getIdToken();
    }
    catch (\Exception $e) {
      return $this->failLogin(t('There was a problem logging you in, sorry for the inconvenience.'), 
        'Failed to exchange code for tokens: ' . $e->getMessage());
    }

    /**
     * Validate the ID Token
     */
    $auth0_domain = 'https://' . $this->domain . '/';
    $auth0_settings = array();
    $auth0_settings['authorized_iss'] = [$auth0_domain];
    $auth0_settings['supported_algs'] = [$this->auth0_jwt_signature_alg];
    $auth0_settings['valid_audiences'] = [$this->client_id];
    $auth0_settings['client_secret'] = $this->client_secret;
    $auth0_settings['secret_base64_encoded'] = $this->secret_base64_encoded;
    $jwt_verifier = new JWTVerifier($auth0_settings);
    try {
      $user = $jwt_verifier->verifyAndDecode($idToken);
    }
    catch(\Exception $e) {
      return $this->failLogin(t('There was a problem logging you in, sorry for the inconvenience.'), 
        'Failed to verify and decode the JWT: ' . $e->getMessage());
    }

    /**
     * Validate the state if we redirected for login
     */
    $state = 'invalid';
    if ($request->query->has('state')) {
      $state = $request->query->get('state');
    } elseif ($request->request->has('state')) {
      $state = $request->request->get('state');
    }

    if (!$this->compareNonce($state)) {
      return $this->failLogin(t('There was a problem logging you in, sorry for the inconvenience.'),
        "Failed to verify the state ($state)");
    }

    /**
     * Check the sub if it exists (this will exist if you have enabled OIDC Conformant)
     */
    if ($userInfo['sub'] != $user->sub) {
      return $this->failLogin(t('There was a problem logging you in, sorry for the inconvenience.'), 
        'Failed to verify the JWT sub.');
    } elseif (array_key_exists('sub', $userInfo)) {
      $userInfo['user_id'] = $userInfo['sub'];
    }

    if ($userInfo) {
      return $this->processUserLogin($request, $userInfo, $idToken);
    }
    else {
      return $this->failLogin(t('There was a problem logging you in, sorry for the inconvenience.'), 
        'No userInfo found');
    }
  }

  /**
   * Checks if the email is valid.
   */
  protected function validateUserEmail($userInfo) {
    $config = \Drupal::service('config.factory')->get('auth0.settings');
    $requires_email = $config->get('auth0_requires_verified_email');

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
   */
  protected function processUserLogin(Request $request, $userInfo, $idToken) {
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

    // See if there is a user in the auth0_user table with the user info client id.
    $user = $this->findAuth0User($userInfo['user_id']);
    
    if ($user) {
      // User exists!
      // update the auth0_user with the new userInfo object.
      $this->updateAuth0User($userInfo);

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

      $this->insertAuth0User($userInfo, $user->id());

      $event = new Auth0UserSignupEvent($user, $userInfo);
      $this->eventDispatcher->dispatch(Auth0UserSignupEvent::NAME, $event);
    }

    user_login_finalize($user);

    if ($request->request->has('destination')) {
      return $this->redirect($request->request->get('destination'));
    }

    return $this->redirect('entity.user.canonical', array('user' => $user->id()));
  }

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
   */
  protected function signupUser($userInfo, $idToken) {
    // If the user doesn't exist we need to either create a new one, or assign him to an existing one.
    $isDatabaseUser = FALSE;

    /* Make sure we have the identities array, if not, fetch it from the user endpoint */
    $hasIdentities = (is_object($userInfo) && $userInfo->has('identities')) ||
      (is_array($userInfo) && array_key_exists('identities', $userInfo));
    if (!$hasIdentities) {
      $mgmtClient = new Management($idToken, $this->domain);

      $user = $mgmtClient->users->get($userInfo['user_id']);
      $userInfo['identities'] = $user['identities'];
    }

    foreach ($userInfo['identities'] as $identity) {
      if ($identity['provider'] == "auth0") {
        $isDatabaseUser = TRUE;
      }
    }
    $joinUser = FALSE;

    // If the user has a verified email or is a database user try to see if there is
    // a user to join with. The isDatabase is because we don't want to allow database
    // user creation if there is an existing one with no verified email.
    if ($userInfo['email_verified'] || $isDatabaseUser) {
      $joinUser = user_load_by_mail($userInfo['email']);
    }

    if ($joinUser) {
      // If we are here, we have a potential join user.
      // Don't allow creation or assignation of user if the email is not verified,
      // that would be hijacking.
      if (!$userInfo['email_verified']) {
        throw new EmailNotVerifiedException();
      }
      $user = $joinUser;
    }
    else {
      // If we are here, we need to create the user.
      $user = $this->createDrupalUser($userInfo);
    }

    return $user;
  }

  /**
   * Email not verified error message.
   */
  protected function auth0FailWithVerifyEmail($idToken) {

    $url = Url::fromRoute('auth0.verify_email', array(), array());
    $formText = "<form style='display:none' name='auth0VerifyEmail' action=@url method='post'><input type='hidden' value=@token name='idToken'/></form>";
    $linkText = "<a href='javascript:null' onClick='document.forms[\"auth0VerifyEmail\"].submit();'>here</a>";

    return $this->failLogin(
      t($formText."Please verify your email and log in again. Click $linkText to Resend verification email.",
        array(
          '@url' => $url->toString(),
          '@token' => $idToken
        )
    ), 'Email not verified');
  }

  /**
   * Get the auth0 user profile.
   */
  protected function findAuth0User($id) {
    $auth0_user = db_select('auth0_user', 'a')
        ->fields('a', array('drupal_id'))
        ->condition('auth0_id', $id, '=')
        ->execute()
        ->fetchAssoc();

    return empty($auth0_user) ? FALSE : User::load($auth0_user['drupal_id']);
  }

  /**
   * Update the auth0 user profile.
   */
  protected function updateAuth0User($userInfo) {
    db_update('auth0_user')
        ->fields(array(
            'auth0_object' => serialize($userInfo)
        ))
        ->condition('auth0_id', $userInfo['user_id'], '=')
        ->execute();
  }

  /**
   * Insert the auth0 user.
   */
  protected function insertAuth0User($userInfo, $uid) {

    db_insert('auth0_user')->fields(array(
        'auth0_id' => $userInfo['user_id'],
        'drupal_id' => $uid,
        'auth0_object' => json_encode($userInfo)
      ))->execute();

  }

  private function getRandomBytes($nbBytes = 32) {
    $bytes = openssl_random_pseudo_bytes($nbBytes, $strong);
    if (false !== $bytes && true === $strong) {
        return $bytes;
    }
    else {
        throw new \Exception("Unable to generate secure token from OpenSSL.");
    }
  }

  private function generatePassword($length){
    return substr(preg_replace("/[^a-zA-Z0-9]\+\//", "", base64_encode($this->getRandomBytes($length+1))),0,$length);
  }

  /**
   * Create the Drupal user based on the Auth0 user profile.
   */
  protected function createDrupalUser($userInfo) {

    $user = User::create();

    $user->setPassword($this->generatePassword(16));
    $user->enforceIsNew();

    if (isset($userInfo['email']) && !empty($userInfo['email'])) {
      $user->setEmail($userInfo['email']);
    }
    else {
      $user->setEmail("change_this_email@" . uniqid() . ".com");
    }

    // If the username already exists, create a new random one.
    $username = $userInfo['nickname'];
    if (user_load_by_name($username)) {
      $username .= time();
    }

    $user->setUsername($username);
    $user->activate();
    $user->save();

    return $user;
  }

  /**
   * Send the verification email.
   */
  public function verify_email(Request $request) {
    $idToken = $request->get('idToken');

    /**
      * Validate the ID Token
      */
    $auth0_domain = 'https://' . $this->domain . '/';
    $auth0_settings = array();
    $auth0_settings['authorized_iss'] = [$auth0_domain];
    $auth0_settings['supported_algs'] = [$this->auth0_jwt_signature_alg];
    $auth0_settings['valid_audiences'] = [$this->client_id];
    $auth0_settings['client_secret'] = $this->client_secret;
    $auth0_settings['secret_base64_encoded'] = $this->secret_base64_encoded;
    $jwt_verifier = new JWTVerifier($auth0_settings);
    try {
      $user = $jwt_verifier->verifyAndDecode($idToken);
    }
    catch(\Exception $e) {
      return $this->failLogin(t('There was a problem resending the verification email, sorry for the inconvenience.'), 
        "Failed to verify and decode the JWT ($idToken) for the verify email page: " . $e->getMessage());
    }

    try {
      $userId = $user->sub;
      $url = "https://$this->domain/api/users/$userId/send_verification_email";
      
      $client = \Drupal::httpClient();
      
      $client->request('POST', $url, array(
          "headers" => array(
            "Authorization" => "Bearer $idToken"
          )
        )
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
