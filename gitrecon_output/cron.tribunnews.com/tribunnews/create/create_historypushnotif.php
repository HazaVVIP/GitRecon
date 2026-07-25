<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include_once DOC_ROOT."config/config.php";
include_once DOC_ROOT."lib/Opensearch.php";


$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = 'tribunnews-historypushnotif_sch';
$tables = array(
		'id' => "integer",
		'id_article' => "integer",
		'user_id' => "integer",
		'fullname' => "keyword",
		"deskripsi" => "text_keyword", 
		"url" => "text",
		"image" => "text",
		"judul" => "text",
		"datepush" => "date"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>