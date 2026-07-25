<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include_once DOC_ROOT."config/config.php";
include_once DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);


$index = 'jadwal_pialadunia';
$tables = array(
		'id' => "integer",
		'kickoff' => "date",
		'tanggal' => "date_only",
		'negara1' => "text_keyword",
		'image_negara1_link' => "text",
		'link_berita_negara1' => "text",
		'penulis_berita_negara1' => "text",
		'skor_negara1' => "integer",
		'negara2' => "text_keyword",
		'image_negara2_link' => "text",
		'link_berita_negara2' => "text",
		'penulis_berita_negara2' => "text",
		'skor_negara2' => "integer",
		'stadium' => "text_keyword",
		'waktu' => "text",
		'no_urut' => "long",
		'position' => "long",
		'date_update' => "text",
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