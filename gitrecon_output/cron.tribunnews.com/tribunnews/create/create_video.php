<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include_once DOC_ROOT."config/config.php";
include_once DOC_ROOT."lib/Opensearch.php";


$opensearch = new Opensearch();
$opensearch->init(OS_URL,OS_USERNAME,OS_PASSWORD,true);

$index = 'tribunnews-video';
$tables = array(
		'id' => "integer",
		'title' => "text",
		'alias' => "text_keyword",
		"topic" => "text", 
		"category" => "text",
		"uploader_source" => "integer",
		"uploader" => "integer",
		"editor_video" => "integer",
		"reporter" => "integer",
		"cameraman" => "integer",
		"source" => "integer",
		"update_date" => "date_null",
		"publish" => "integer",
		"fulltexts" => "text",
		"publish_date" => "date_null",
		"camera_name" => "text",
		"reporter_name" => "text",
		"editor_video_name" => "text",
		"name_source" => "text",
		"uploader_name" => "text",
		"host_id" => "text",
		"host_name" => "text",
		"file" => "text",
		"upload_date" => "date",
		"poster" => "text",
		"views_count" => "integer",
		"tagging" => "nested_tagging",
		"views" => "integer"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>