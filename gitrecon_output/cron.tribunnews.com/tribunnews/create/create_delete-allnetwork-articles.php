<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include_once DOC_ROOT."config/config.php";
include_once DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_ALLNETWOORK_URL,OS_ALLNETWOORK_USERNAME,OS_ALLNETWOORK_PASSWORD,true);

$index = 'delete-allnetwork-articles';
$tables = array(
		'id' => "long",
		'domain_id' => "integer",
		'domain' => "keyword",
		'title' => "text_keyword",
		'alias' => "text_keyword",
		"written_date" => "date",
		"publish_date" => "date",
		"editor_fullname" => "text_keyword",
		"editor_id" => "integer",
		"writter_fullname" => "text_keyword",
		"writter_id" => "integer",
		"delete_editor_id" => "integer",
		"deleted_date" => "date",
		"tag_related" => "text_keyword",
		"index_year" => "date_only_year"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>