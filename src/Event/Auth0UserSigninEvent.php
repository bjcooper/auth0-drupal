<?php

namespace Drupal\auth0\Event;

use Symfony\Component\EventDispatcher\Event;
use Drupal\user\UserInterface;

/**
 * User signin event.
 */
class Auth0UserSigninEvent extends Event {

  const NAME = 'auth0.signin';

  /**
   * The Drupal User.
   *
   * @var \Drupal\user\UserInterface
   */
  protected $user;

  /**
   * The Auth0 Profile.
   *
   * @var array
   */
  protected $auth0Profile;

  /**
   * Initialize the event.
   *
   * @param Drupal\user\UserInterface $user
   *   The drupal user.
   * @param array $auth0Profile
   *   The Auth profile.
   */
  public function __construct(UserInterface $user, array $auth0Profile) {
    $this->user = $user;
    $this->auth0Profile = $auth0Profile;
  }

  /**
   * Get the drupal user.
   *
   * @return \Drupal\user\UserInterface
   *   Return the drupal user.
   */
  public function getUser() {
    return $this->user;
  }

  /**
   * Get the Auth0 profile.
   *
   * @return array
   *   Return the auth profile.
   */
  public function getAuth0Profile() {
    return $this->auth0Profile;
  }

}
