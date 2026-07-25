<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$index = 'widget_quickcount_pilpres2024';
$tables = array(
		'id' => "integer",
		'paslon1' => "float",
		'paslon2' => "float",
		'paslon3' => "float",
		'suaramasuk' => "float",
		'persensuaramasuk' => "float",
		'timestamp1' => "date",
		'created_date' => "date"
	);
$response = $opensearch->create($index,$tables);

echo "<pre>";
print_r($tables);
print_r($response);
echo "</pre>";

unset($opensearch);
?>