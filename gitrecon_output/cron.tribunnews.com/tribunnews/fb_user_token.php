<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

require_once DOC_ROOT.'vendor/facebook/graph-sdk/src/Facebook/autoload.php';

$fb = new Facebook\Facebook([
		  'app_id' => '4016464185280575',
		  'app_secret' => '5c4e08ffae34148ba07d7062258de881',
		  'default_graph_version' => 'v22.0',
		  //'default_access_token' => '{access-token}', // optional
		]);
		
$helper = $fb->getRedirectLoginHelper();

$permissions = ['email','read_insights','pages_read_user_content','pages_manage_metadata','pages_read_engagement','page_events','attribution_read']; // Optional permissions

$loginUrl = $helper->getLoginUrl('https://cron.tribunnews.com/tribunnews/fb_callback.php', $permissions);

echo '<a href="' . $loginUrl . '">Log in with Facebook!</a><hr>';

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>