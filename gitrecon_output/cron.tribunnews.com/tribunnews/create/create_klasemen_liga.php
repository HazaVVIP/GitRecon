<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$liga = isset($_GET['liga'])?$_GET['liga']:"champions";

if(!empty($liga)){
	$opensearch = new Opensearch();
	$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);
	
	$index = "klasemen_liga_".$liga;
	$tables = array(
			'id' => "integer",
			'klub' => "text",
			'group' => "text",
			'image_klub_link' => "text",
			'lima_hasil_terakhir' => "text",
			'flag' => "text",
			"score_D" => "integer",
			"score_GK" => "integer",
			"score_GM" => "integer",
			"score_K" => "integer",
			"score_M" => "integer",
			"score_P" => "integer",
			"score_S" => "integer",
			"score_min_plus" => "integer",
			"urutan" => "integer"
		);
	$response = $opensearch->create($index,$tables);

	echo "<pre>";
	print_r($tables);
	print_r($response);
	echo "</pre>";

	unset($opensearch);
}	
?>