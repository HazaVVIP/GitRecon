<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = 'tribunx-section';
$tables = array(
		'id' => "integer",
		'title' => "text",
		'alias' => "keyword",
		'path_api' => "keyword",
		'image' => "keyword",
		'is_onboard' => "integer",
		'is_view' => "integer",
		'stat' => "integer",
		'is_order' => "integer",
		'is_delete' => "integer",
		"created_date" => "date",
		"modified_date" => "date_null",
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>