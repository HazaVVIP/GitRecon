<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$totalDate = 60;

$dateLog = date("Y-m-d 00:00:00", strtotime('-'.$totalDate.' days'));

echo $dateLog."<br>";

$where = array();
array_push($where,array("range" => array("create_date" => array("lt" =>$dateLog))));	

$condition = array();
if(count($where) > 0){
$condition = array("bool" =>
				array("must" =>
					$where
				)
		);
}		

//OS
$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);
$response = $opensearch->count_total('log',$condition);

$totalOs = 0;
$arrIDOs = array();
if($response['status']){
	$totalOs = isset($response['total'])?$response['total']:0;
}

$desc = "";
if($totalOs > 0){
	$response_delete = $opensearch->deleteMany('log',$condition);
	
	$status_delete = isset($response_delete['status'])?$response_delete['status']:0;
	if($status_delete) $desc = "Berhasil di Hapus";
}	

echo "Total Log : ".$totalOs." ".$desc."<br>"; 

unset($opensearch);

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>