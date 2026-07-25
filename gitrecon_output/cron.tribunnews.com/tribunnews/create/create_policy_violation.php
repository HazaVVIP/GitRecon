<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = 'policy_violation';
$tables = array(
		'id' => "integer",
		'id_article' => "integer",
		'title' => "text",
		"alias" => "text_keyword", 
		"domain" => "keyword",
		"must_fix" => "keyword",
		"side_news" => "keyword",
		"side_news_title" => "keyword",
		"status" => "integer",
		"date_report" => "date",
		"publish_date" => "date",
		"writter" => "integer",
		"writter_id" => "integer",
		"writter_fullname" => "text_keyword",
		"editor" => "integer",
		"editor_id" => "integer",
		"editor_fullname" => "text_keyword",
		"insert_date" => "date",
		"update_date" => "date_null"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>