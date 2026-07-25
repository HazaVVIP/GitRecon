<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include_once DOC_ROOT."config/config.php";
include_once DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = 'tribunx-tagpilihan';
$tables = array(
		'id' => "integer",
		'tag' => "text",
		'stat' => "integer",
		'articles' => "nested_artices",
		"created_date" => "date",
		"modified_date" => "date_null"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>