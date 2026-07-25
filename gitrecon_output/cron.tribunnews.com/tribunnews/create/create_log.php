<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = 'log';
$tables = array(
		'id' => "integer",
		'domain' => "text_keyword",
		"module" => "text_keyword", 
		"action" => "text_keyword",
		"value" => "text",
		"editor_by" => "integer",
		"editor_username" => "text_keyword",
		"ip_addr" => "keyword",
		"create_date" => "date"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>