<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = "topskorassist";
$tables = array(
		'id' => "integer",
		'liga' => "keyword",
		'player_name' => "keyword",
		'klub' => "keyword",
		'image_klub_link' => "text",
		'jenis' => "keyword",
		"val" => "integer",
		"urutan" => "integer"
	);
$response = $opensearch->create($index,$tables);

echo $index;
echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
	
?>