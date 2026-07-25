<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include_once DOC_ROOT."config/config.php";
include_once DOC_ROOT."lib/Opensearch.php";


$opensearch = new Opensearch();
$opensearch->init(OS_URL,OS_USERNAME,OS_PASSWORD,true);

$index = 'tribunnews-populer-ga-articles';
$tables = array(
		'id' => 'integer',
		"title" => "text", 
		"alias" => "keyword",
		"category" => "text", 
		"category_id" => "integer", 
		"section" => "text", 
		"section_id" => "section_id", 
		"publish_date" => "date", 
		"written_date" => "date", 
		"foto_name" => "text", 
		"foto_type" => "text", 
		"introtext" => "text",
		"editor_by" => "integer",
		"editor_fullname" => "text",
		"written_by" => "integer",
		"writter_fullname" => "text",
		"rank" => "integer",
		"pageviews" => "integer"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>