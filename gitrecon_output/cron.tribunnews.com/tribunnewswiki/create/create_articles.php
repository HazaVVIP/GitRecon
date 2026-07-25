<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
//$opensearch->init(OS_TNEWSWIKI_URL,OS_TNEWSWIKI_USERNAME,OS_TNEWSWIKI_PASSWORD,true);
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = 'tribunnewswiki-articles';
$tables = array(
		"id" => "integer", 
		"title" => "text",
		"introtext" => "text",
		"fulltexts" => "text", 
		"detail" => "text_keyword", 
		"sumber" => "text_keyword", 
		"alias" => "text_keyword", 
		"foto_type" => "text_keyword",
		"foto_name" => "text_keyword", 
		"foto_caption" => "text_keyword", 
		"foto_source" => "text_keyword",				
		"publish_date" => "date",
		"written_date" => "date",
		"writter_fullname" => "text_keyword",
		"writter_username" => "text_keyword",
		"written_by" => "integer",
		"editor" => "text_keyword",
		"editor_fullname" => "text_keyword",
		"editor_by" => "integer",
		"wikiblog" => "integer",
		"publish" => "integer",
		"subtitle" => "text_keyword",
		"subtitle_alias" => "text_keyword",
		"type_content" => "text_keyword",
		"geographis" => "text_keyword",
		"tagging" => "nested_tagging",
		"modified_date" => "date_null",
		"penulis_related" => "nested_penulis_related",
		"hit" => "integer"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>