<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include_once DOC_ROOT."config/config.php";
include_once DOC_ROOT."lib/Opensearch.php";


$opensearch = new Opensearch();
$opensearch->init(OS_URL,OS_USERNAME,OS_PASSWORD,true);

$index = 'tribunnews-populer-ga-tagtopic';
$tables = array(
		'id' => 'text',
		'title' => 'text',
		"mode" => "text", 
		"rank" => "integer",
		"section" => "text"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>