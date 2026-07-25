<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

/* 
Running in cmd / command
- sudo -u cron /usr/bin/php7.4 /var/www/html/web-cron/tribunnews/privacy_policy/delete_privacy.php 
*/

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$totalDate = 2;

$dateLog = date("Y-m-d 00:00:00", strtotime('+'.$totalDate.' days'));

echo $dateLog."<br>";

$index_name = "policy_violation";
$where = array();
array_push($where,array("match" => array("status" => 0)));
array_push($where,array("range" => array("insert_date" => array("lt" =>$dateLog))));	

$condition = array();
if(count($where) > 0){
$condition = array("bool" =>
				array("must" =>
					$where,
					"must_not" =>
					array("exists" => array("field" => "publish_date"))
				)
		);
}		

//OS
$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);
$response = $opensearch->count_total($index_name,$condition);

$totalOs = 0;
$arrIDOs = array();
if($response['status']){
	$totalOs = isset($response['total'])?$response['total']:0;
}

$desc = "";
if($totalOs > 0){
	$response_delete = $opensearch->deleteMany($index_name,$condition);
	
	$status_delete = isset($response_delete['status'])?$response_delete['status']:0;
	if($status_delete) $desc = "Berhasil di Hapus";
}	

echo "Total Privacy Policy : ".$totalOs." ".$desc."<br>"; 

unset($opensearch);

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>