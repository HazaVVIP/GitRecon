<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = 'pilpres2024';
$tables = array(
		'id' => "text",
		'domain_id' => "integer",
		'profil' => "text_keyword",
		'title' => "text",
		'article_url' => "text_keyword",
		'photo_url' => "text_keyword",
		'introtext' => "text_keyword",
		'publish_date' => "date_null"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>