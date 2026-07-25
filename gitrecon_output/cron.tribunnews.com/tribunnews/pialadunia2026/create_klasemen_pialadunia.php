<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include_once DOC_ROOT."config/config.php";
include_once DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = 'klasemen_pialadunia';
$tables = array(
		'id' => "integer",
		'negara' => "text_keyword",
		'negara_eng' => "text_keyword",
		'urutan' => "integer",
		'score_D' => "integer",
		'score_M' => "integer",
		'score_S' => "integer",
		'score_K' => "integer",
		'score_GM' => "integer",
		'score_GK' => "integer",
		'score_min_plus' => "integer",
		'score_P' => "integer",
		'image_negara_link' => "text_keyword",
		'penulis_berita_negara' => "text_keyword",
		'link_berita_negara' => "text_keyword",
		'created_date' => 'date',
		'modified_date' => 'date_null',
		'index_year' => 'date_only_year'
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>