<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = "klasemen_penyisihan";
$tables = array(
		'id' => "integer",
		'aggregate' => "text",
		'image_klub_1' => "text",
		'image_klub_2' => "text",
		'klub_initial_1' => "text",
		'klub_initial_2' => "text",
		'label_fase' => "text",
		'liga' => "text",
		"fase" => "integer",
		"skor_klub_1" => "integer",
		"skor_klub_2" => "integer"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>