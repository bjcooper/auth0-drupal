<?php
namespace Drupal\auth0\Event;

use Symfony\Component\EventDispatcher\Event;

/**
 * User signin event.
 */
class Auth0UserSigninEvent extends Event {
  
  const NAME = 'auth0.signin';

  /**
   * @var \Drupal\user\UserInterface
   */
  protected $user;

  /**
   * @var array
   */
  protected $auth0Profile;

  /**
   * Initialize the event.
   * @param \Drupal\user\UserInterface $user
   * @param array $auth0Profile
   */
  public function __construct($user, $auth0Profile) {
    $this->user = $user;
    $this->auth0Profile = $auth0Profile;
  }

  /**
   * Get the drupal user.
   * @return \Drupal\user\UserInterface
   */
  public function getUser() {
    return $this->user;
  }

  /**
   * Get the Auth0 profile.
   * @return array
   */
  public function getAuth0Profile() {
    return $this->auth0Profile;
  }

}
