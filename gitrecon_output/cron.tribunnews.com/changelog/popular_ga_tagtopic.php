<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
ini_set("memory_limit", "-1");
set_time_limit(0);

$time_start = time();
include "config/config.php";
include "lib/Opensearch.php";
include "lib/Writelog.php";

$writelog = new Writelog();
$writelog->Log(PATH_ROOT."/logs/","tribunnews-populer-ga-tagtopic");

$total = 0;	

$elasticsearch = new Opensearch();
$elasticsearch->init(ES_URL,"","",false);

$opensearch = new Opensearch();
$opensearch->init(OS_URL,OS_USERNAME,OS_PASSWORD,true);

$condition = array("match_all"=>new stdClass);
$fields = array();
$sort = array("rank" => "asc");
$start = 0;
$limit = 500;
$response = $elasticsearch->find('tribunnews-populer-ga-tagtopic',$condition,$fields,$sort,$start,$limit);

if($response['status']){
	$totalData = isset($response['total_row'])?$response['total_row']:0;
	$arrPosts = isset($response['data'])?$response['data']:null;
	
	if($totalData > 0){
		foreach($arrPosts as $idx => $post){
			$id 				= isset($post['_source']['id'])?$post['_source']['id']:"";
			$title 				= isset($post['_source']['title'])?$post['_source']['title']:"";
			$mode 				= isset($post['_source']['mode'])?$post['_source']['mode']:"";
			$rank 				= isset($post['_source']['rank'])?intval($post['_source']['rank']):0;
			$section 			= isset($post['_source']['section'])?$post['_source']['section']:"";
			
			/* echo "<pre>";
			print_r($post);
			echo "</pre>"; */
			
			$arrInsert = array();
			$arrInsert['id'] = $id;
			$arrInsert['title'] = $title;
			$arrInsert['mode'] = $mode;
			$arrInsert['rank'] = $rank;
			$arrInsert['section'] = $section;
			
			/* echo "<pre>";
			print_r($arrInsert);
			echo "</pre>"; */
			
			$responseInsert = $opensearch->insert("tribunnews-populer-ga-tagtopic", $arrInsert);

			if($responseInsert['status']){
				$total++; 
			}
			
			$lastid = $id;
		}	
	} else {
		/* $lastid = "";
		if (!$handle = fopen($filename, 'w+')) {
			die("Cannot open file $filename");
		}
		if (fwrite($handle, $lastid) === FALSE) {
			die("Cannot write to file $this->log_file");
		} */
	}
	
	echo "TOTAL : " . $totalData . "\n";
	echo "TOTAL MIGRASI : " . $total . "\n";
	echo "LAST ID : " . $lastid . "\n";

	$loginfo = "TOTAL = ".$totalData." | TOTAL MIGRASI = ".$total." | LAST ID = ".$lastid."\n";
	$writelog->doLogInfo($loginfo);
}

$writelog->closeLog();
unset($elasticsearch);

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>