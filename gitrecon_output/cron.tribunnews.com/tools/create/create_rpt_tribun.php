<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = "rpt_rekap_tribunnews";
$tables = array(
		'id' => "integer",
		"dt" => "date",
		"tot_usr_reg" => "integer",
		"tot_usrtnews_reg" => "integer",
		"tot_usrtjb_reg" => "integer",
		"tot_usrtnewswiki_reg" => "integer",
		"tot_usrtribunsuperapps_reg" => "integer",
		"tot_artc" => "integer",
		"tot_artc_tnews" => "integer",
		"tot_artc_tbo" => "integer",
		"tot_artc_commerce" => "integer",
		"tot_artc_daerah" => "integer",
		"tot_artc_tbo_detail" => "nested_report",
		"tot_artc_commerce_detail" => "nested_report",
		"tot_artc_daerah_detail" => "nested_report",
		"tot_pv" => "integer",
		"tot_pv_tnews" => "integer",
		"tot_pv_tbo" => "integer",
		"tot_pv_commerce" => "integer",
		"tot_pv_daerah" => "integer",
		"tot_pv_tbo_detail_new" => "nested_report",
		"tot_pv_commerce_detail_new" => "nested_report",
		"tot_pv_daerah_detail_new" => "nested_report",
		"tot_vid" => "integer",
		"tot_pv_video" => "integer",
		"tot_artc_tnewswiki" => "integer",
		"tot_pv_tnewswiki" => "integer",
		"written_date" => "date"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>