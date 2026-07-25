<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = 'jadwal_imsak';
$tables = array(
		'id' => "integer",
		'city_name' => "keyword",
		'city_alias' => "keyword",
		'province_name' => "keyword",
		'province_alias' => "keyword",
		"hari_ke" => "integer",
		"imsak" => "text",
		"subuh" => "text",
		"terbit" => "text",
		"duha" => "text",
		"zuhur" => "text",
		"asar" => "text",
		"magrib" => "text",
		"thn" => "date_only_year",
		"create_date" => "date"
		
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>