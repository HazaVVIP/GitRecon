<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include_once DOC_ROOT."config/config.php";
include_once DOC_ROOT."lib/Opensearch.php";


$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = 'network-bizz';
$tables = array(
		'id' => "text",
		'title' => "text_keyword",
		'introtext' => "text_keyword",
		'domain' => "keyword",
		'urlpage' => "keyword",
		'image' => "text_keyword",
		'urutan' => "keyword",
		'datepub' => "date",
		'datecr' => "date"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>