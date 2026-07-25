<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include_once DOC_ROOT."config/config.php";
include_once DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = 'widget_emasperak';
$tables = array(
		'id' => "keyword",
		'jenis' => "keyword",
		'nilai' => "float",
		'satuan' => "keyword",
		'tipe' => "keyword",
		'sumber' => "text_keyword",
		'source' => "keyword",
		'tanggal_kurs' => "text_keyword",
		"tanggal_dt" => "date_only",
		"tanggal_fetch" => "date"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>