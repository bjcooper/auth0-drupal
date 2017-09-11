<?php

namespace Drupal\auth0\Event;

use Symfony\Component\EventDispatcher\Event;
use Drupal\user\UserInterface;

/**
 * User signin event.
 */
class Auth0UserSigninEvent extends Event {

  /**
   * The event name.
   */
  const NAME = 'auth0.signin';

  /**
   * The user.
   *
   * @var \Drupal\user\UserInterface
   */
  protected $user;

  /**
   * The auth0 profile.
   *
   * @var array
   */
  protected $auth0Profile;

  /**
   * Initialize the event.
   *
   * @param \Drupal\user\UserInterface $user
   *   The user.
   * @param array $auth0Profile
   *   The auth0 profile.
   */
  public function __construct(UserInterface $user, array $auth0Profile) {
    $this->user = $user;
    $this->auth0Profile = $auth0Profile;
  }

  /**
   * Get the drupal user.
   *
   * @return \Drupal\user\UserInterface
   *   The user object.
   */
  public function getUser() {
    return $this->user;
  }

  /**
   * Get the Auth0 profile.
   *
   * @return array
   *   The auth0 user info.
   */
  public function getAuth0Profile() {
    return $this->auth0Profile;
  }

}
