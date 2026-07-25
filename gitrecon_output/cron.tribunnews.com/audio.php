<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();
include "config/config.php";
include "lib/Opensearch.php";
include "lib/Writelog.php";

$writelog = new Writelog();
$writelog->Log(PATH_ROOT."/logs/","tribunnews-audio");

$total = 0;	

$elasticsearch = new Opensearch();
$elasticsearch->init(ES_URL,"","",false);

$opensearch = new Opensearch();
$opensearch->init(OS_URL,OS_USERNAME,OS_PASSWORD,true);

$condition = array("match_all"=>new stdClass);
$fields = array();
$sort = array("id" => "asc");
$start = 0;
$limit = 100;
$response = $elasticsearch->find('tribunnews-audio',$condition,$fields,$sort,$start,$limit);

if($response['status']){
	$totalData = isset($response['total_row'])?$response['total_row']:0;
	$arrPosts = isset($response['data'])?$response['data']:null;
	
	if($totalData > 0){
		foreach($arrPosts as $idx => $post){
			$id 				= isset($post['_source']['id'])?intval($post['_source']['id']):"";
			$audio_html 		= isset($post['_source']['audio_html'])?$post['_source']['audio_html']:"";
			$audio_source 		= isset($post['_source']['audio_source'])?$post['_source']['audio_source']:"";
			$related_type 		= isset($post['_source']['related_type'])?$post['_source']['related_type']:"";
			$url_source 		= isset($post['_source']['url_source'])?$post['_source']['url_source']:"";
			$insert_by 			= isset($post['_source']['insert_by'])?intval($post['_source']['insert_by']):0;
			$insert_date 		= isset($post['_source']['insert_date'])?$post['_source']['insert_date']:"";
			$related_id 		= isset($post['_source']['related_id'])?$post['_source']['related_id']:0;
			
			/* echo "<pre>";
			print_r($post);
			echo "</pre>"; */
			
			$arrInsert = array();
			$arrInsert['id'] = $id;
			$arrInsert['audio_html'] = $audio_html;
			$arrInsert['audio_source'] = $audio_source;
			$arrInsert['related_type'] = $related_type;
			$arrInsert['url_source'] = $url_source;
			$arrInsert['insert_by'] = $insert_by;
			$arrInsert['insert_date'] = $insert_date;
			$arrInsert['related_id'] = $related_id;
			
			$responseInsert = $opensearch->insert("tribunnews-audio", $arrInsert);

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