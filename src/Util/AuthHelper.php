<?php

namespace Drupal\auth0\Util;

/**
 * @file
 * Contains \Drupal\auth0\Util\AuthHelper.
 */

use Auth0\SDK\API\Authentication;
use Auth0\SDK\Auth0;
use Auth0\SDK\Configuration\SdkConfiguration;
use Drupal\auth0\Exception\RefreshTokenFailedException;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;

/**
 * Controller routines for auth0 authentication.
 */
class AuthHelper {
  const AUTH0_LOGGER = 'auth0_helper';
  const AUTH0_DOMAIN = 'auth0_domain';
  const AUTH0_CUSTOM_DOMAIN = 'auth0_custom_domain';
  const AUTH0_CLIENT_ID = 'auth0_client_id';
  const AUTH0_CLIENT_SECRET = 'auth0_client_secret';
  const AUTH0_REDIRECT_FOR_SSO = 'auth0_redirect_for_sso';
  const AUTH0_JWT_SIGNING_ALGORITHM = 'auth0_jwt_signature_alg';
  const AUTH0_SECRET_ENCODED = 'auth0_secret_base64_encoded';
  const AUTH0_OFFLINE_ACCESS = 'auth0_allow_offline_access';

  /**
   * The logger.
   *
   * @var \Drupal\Core\Logger\LoggerChannelInterface
   */
  private $logger;

  /**
   * The config.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  private $config;

  /**
   * The Auth0 Domain.
   *
   * @var string
   */
  private $domain;

  /**
   * An optional custom Auth0 domain.
   *
   * @var string
   */
  private $customDomain;

  /**
   * The Auth0 client ID.
   *
   * @var string
   */
  private $clientId;

  /**
   * The Auth0 client secret.
   *
   * @var string
   */
  private $clientSecret;

  /**
   * If should redirect for SSO.
   *
   * @var bool
   */
  private $redirectForSso;

  /**
   * The auth0 token algorithm.
   *
   * @var string
   */
  private $auth0JwtSignatureAlg;

  /**
   * If secret is base 64 encoded or not.
   *
   * @var bool
   */
  private $secretBase64Encoded;

  /**
   * An instance of the Auth0 SDK.
   *
   * @var \Auth0\SDK\Auth0|null
   */
  private $sdk;

  /**
   * Initialize the Helper.
   *
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   */
  public function __construct(
    LoggerChannelFactoryInterface $logger_factory,
    ConfigFactoryInterface $config_factory
  ) {
    $this->logger = $logger_factory->get(AuthHelper::AUTH0_LOGGER);
    $this->config = $config_factory->get('auth0.settings');
    $this->domain = $this->config->get(AuthHelper::AUTH0_DOMAIN);
    $this->customDomain = $this->config->get(AuthHelper::AUTH0_CUSTOM_DOMAIN);
    $this->clientId = $this->config->get(AuthHelper::AUTH0_CLIENT_ID);
    $this->clientSecret = $this->config->get(AuthHelper::AUTH0_CLIENT_SECRET);
    $this->redirectForSso = $this->config->get(AuthHelper::AUTH0_REDIRECT_FOR_SSO);
    $this->auth0JwtSignatureAlg = $this->config->get(
      AuthHelper::AUTH0_JWT_SIGNING_ALGORITHM,
      AUTH0_DEFAULT_SIGNING_ALGORITHM
    );
    $this->secretBase64Encoded = FALSE || $this->config->get(AuthHelper::AUTH0_SECRET_ENCODED);
    $this->auth0Sdk = NULL;

    self::setTelemetry();
  }

  /**
   * Get the user using token.
   *
   * @param string $refreshToken
   *   The refresh token to use to get the user.
   *
   * @return array
   *   A user array of named claims from the ID token.
   *
   * @throws \Drupal\auth0\Exception\RefreshTokenFailedException
   *   An auth0 refresh token failed exception.
   */
  public function getUserUsingRefreshToken($refreshToken) {
    $auth0Api = new Authentication($this->getAuthDomain(), $this->clientId, $this->clientSecret);

    try {
      $tokens = $auth0Api->refreshToken($refreshToken);
      return $this->validateIdToken($tokens->idToken);
    }
    catch (\Exception $e) {
      throw new RefreshTokenFailedException($e);
    }
  }

  /**
   * Validate the ID token.
   *
   * @param string $idToken
   *   The ID token to validate.
   *
   * @return mixed
   *   A user array of named claims from the ID token.
   */
  public function validateIdToken($idToken) {
    return $this->getSdk()->decode($idToken);
  }

  /**
   * Gets the Auth0 SDK.
   *
   * @return \Auth0\SDK\Auth0
   *   An initialized Auth0 SDK instance.
   */
  public function getSdk() {
    if (!$this->sdk) {
      $auth0_domain = 'https://' . $this->getAuthDomain() . '/';
      $auth0_settings['supported_algs'] = [$this->auth0JwtSignatureAlg];
      $auth0_settings['valid_audiences'] = [$this->clientId];
      $auth0_settings['client_secret'] = $this->clientSecret;
      $auth0_settings['secret_base64_encoded'] = $this->secretBase64Encoded;

      $configuration = new SdkConfiguration([
        'domain' => $auth0_domain,
        'clientId' => $this->clientId,
        'clientSecret' => $this->clientSecret,
        'audience' => [$this->clientId],
        'tokenAlgorithm' => $this->auth0JwtSignatureAlg,
      ]);
      $this->sdk = new Auth0($configuration);
    }
    return $this->sdk;
  }

  /**
   * Extend Auth0 PHP SDK telemetry to report for Drupal.
   */
  public static function setTelemetry() {
    // $oldInfoHeaders = HttpClient::getInfoHeadersData();
    // if ($oldInfoHeaders) {
    //   $infoHeaders = HttpTelemetry::Extend($oldInfoHeaders);
    //   $infoHeaders->setEnvProperty('drupal', \Drupal::VERSION);
    //   $infoHeaders->setPackage('auth0-drupal', AUTH0_MODULE_VERSION);
    //   HttpClient::setInfoHeadersData($infoHeaders);
    // }
  }

  /**
   * Return the custom domain, if one has been set.
   *
   * @return mixed
   *   A string with the domain name
   *   A empty string if the config is not set
   */
  public function getAuthDomain() {
    return !empty($this->customDomain) ? $this->customDomain : $this->domain;
  }

  /**
   * Get the tenant CDN base URL based on the Application domain.
   *
   * @param string $domain
   *   Tenant domain.
   *
   * @return string
   *   Tenant CDN base URL
   */
  public static function getTenantCdn($domain) {
    preg_match('/^[\w\d\-_0-9]+\.([\w\d\-_0-9]*)[\.]*auth0\.com$/', $domain, $matches);
    return 'https://cdn' .
      (empty($matches[1]) || $matches[1] == 'us' ? '' : '.' . $matches[1])
      . '.auth0.com';
  }

}
