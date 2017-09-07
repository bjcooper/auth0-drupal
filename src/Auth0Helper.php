<?php

namespace Drupal\Auth0;

use Drupal\user\Entity\User;
use Drupal\Core\Session\SessionManagerInterface;
use Drupal\user\PrivateTempStoreFactory;
use RandomLib\Factory;

/**
 * Helper for Auth0.
 */
class Auth0Helper {

  const SESSION = '';
  const NONCE = 'nonce';
  const AUTH0_LOGGER = '';
  const AUTH0_DOMAIN = 'auth0_domain';
  const AUTH0_CLIENT_ID = 'auth0_client_id';
  const AUTH0_CLIENT_SECRET = 'auth0_client_secret';
  const AUTH0_REDIRECT_FOR_SSO = 'auth0_redirect_for_sso';
  const AUTH0_JWT_SIGNING_ALGORITHM = 'auth0_jwt_signature_alg';
  const AUTH0_SECRET_ENCODED = 'auth0_secret_base64_encoded';

  protected $config;

  protected $sessionManager;

  protected $tempStore;

  /**
   * Auth0Helper constructor.
   * @param $config
   * @param \Drupal\Core\Session\SessionManagerInterface $sessionManager
   * @param \Drupal\user\PrivateTempStoreFactory $tempStoreFactory
   */
  public function __construct($config, SessionManagerInterface $sessionManager,  PrivateTempStoreFactory $tempStoreFactory) {

    $this->config = $config->get('auth0.settings');
    $this->sessionManager = $sessionManager;
    $this->tempStore = $tempStoreFactory->get('auth0');

    $this->domain = $this->config->get(self::AUTH0_DOMAIN);
    $this->client_id = $this->config->get(self::AUTH0_CLIENT_ID);
    $this->client_secret = $this->config->get(self::AUTH0_CLIENT_SECRET);
    $this->redirect_for_sso = $this->config->get(self::AUTH0_REDIRECT_FOR_SSO);
    $this->auth0_jwt_signature_alg = $this->config->get(self::AUTH0_JWT_SIGNING_ALGORITHM);
    $this->secret_base64_encoded = FALSE || $this->config->get(self::AUTH0_SECRET_ENCODED);
  }

  public function getAuth0Settings() {
    global $base_root;

    $lockExtraSettings = $this->config->get('auth0_lock_extra_settings');

    $lockExtraSettings = empty($lockExtraSettings) ? NULL : $lockExtraSettings;

    return [
      'clientId' =>  $this->config->get('auth0_client_id'),
      'domain' => $this->config->get('auth0_domain'),
      'lockOptions' => $lockExtraSettings,
      'showSignup' => $this->config->get('auth0_allow_signup'),
      'callbackURL' => "$base_root/auth0/callback",
      'state' => $this->getNonce(),
    ];

  }

  /**
   * Get the auth0 user profile.
   */
  public function findAuth0User($id) {
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
  public function updateAuth0User($userInfo) {
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
  public function insertAuth0User($userInfo, $uid) {

    db_insert('auth0_user')->fields(array(
      'auth0_id' => $userInfo['user_id'],
      'drupal_id' => $uid,
      'auth0_object' => json_encode($userInfo)
    ))->execute();

  }

  /**
   * Create the Drupal user based on the Auth0 user profile.
   *
   * @param array $userInfo
   *   User info from auth0.
   * @return \Drupal\Core\Entity\EntityInterface|static
   */
  public function createDrupalUser($userInfo) {

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
   * Create a new nonce in session and return it
   *
   * @return mixed
   *   The nonce to authenticate.
   *
   * @throws \Drupal\user\TempStoreException
   */
  public function getNonce() {
    // Have to start the session after putting something into the session, or we don't actually start it!
    if (!$this->sessionManager->isStarted() && !isset($_SESSION['auth0_is_session_started'])) {
      $_SESSION['auth0_is_session_started'] = 'yes';
      $this->sessionManager->start();
    }

    $factory = new Factory;
    $generator = $factory->getMediumStrengthGenerator();
    $nonces = $this->tempStore->get(Auth0Helper::NONCE);

    if (!is_array($nonces)) {
      $nonces = array();
    }

    $nonce = base64_encode($generator->generate(32));
    $newNonceArray = array_merge($nonces, [$nonce]);
    $this->tempStore->set(Auth0Helper::NONCE, $newNonceArray);

    return $nonce;
  }


  /**
   * Do our one-time check against the nonce stored in session
   */
  public function compareNonce($nonce) {
    $nonces = $this->tempStore->get(Auth0Helper::NONCE);
    if (!is_array($nonces)) {
      $this->logger->error("Couldn't verify state because there was no nonce in storage");
      return FALSE;
    }
    $index = array_search($nonce,$nonces);
    if ($index !== FALSE) {
      unset($nonces[$index]);
      $this->tempStore->set(Auth0Helper::NONCE, $nonces);
      return TRUE;
    }

    $this->logger->error("$nonce not found in: ".implode(',', $nonces));
    return FALSE;
  }
}
