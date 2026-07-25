<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();
include "config/config.php";
include "lib/Opensearch.php";
include "lib/Writelog.php";

$writelog = new Writelog();
$writelog->Log(PATH_ROOT."/logs/","tribunnews-video");

$lastid = 0;
$total = 0;
$filename = PATH_ROOT . "/data/lastid_video.txt";
$valueLog = file_get_contents($filename);
if ($valueLog !== FALSE) {
	$lastid = $valueLog;
}

$elasticsearch = new Opensearch();
$elasticsearch->init(ES_URL,"","",false);

$opensearch = new Opensearch();
$opensearch->init(OS_URL,OS_USERNAME,OS_PASSWORD,true);

if (empty($lastid)) {
	$condition = array("match_all"=>new stdClass);
	$fields = array();
	$sort = array("id" => "asc");
	$start = 0;
	$limit = 1000;
	$response = $elasticsearch->find('tribunnews-video',$condition,$fields,$sort,$start,$limit);
	
	$response_total = $elasticsearch->count_total('tribunnews-video',$condition);
} else {
	$condition = array("range"=>array("id"=>array("gt"=>$lastid)));
	$fields = array();
	$sort = array("id" => "asc");
	$start = 0;
	$limit = 1000;
	$response = $elasticsearch->find('tribunnews-video',$condition,$fields,$sort,$start,$limit);
	
	$response_total = $elasticsearch->count_total('tribunnews-video',$condition);
}
	
if($response['status']){
	$totalData = 0;
	if($response_total['status']){
		$totalData = isset($response_total['total'])?$response_total['total']:0;
	} 
	$arrPosts = isset($response['data'])?$response['data']:null;
	
	if($totalData > 0){
		foreach($arrPosts as $idx => $post){
			$id 						= isset($post['_source']['id'])?intval($post['_source']['id']):"";
			$title 						= isset($post['_source']['title'])?$post['_source']['title']:"";
			$alias 						= isset($post['_source']['alias'])?$post['_source']['alias']:"";
			$topic 						= isset($post['_source']['topic'])?$post['_source']['topic']:"";
			$category 					= isset($post['_source']['category'])?$post['_source']['category']:"";
			$uploader_source 			= isset($post['_source']['uploader_source'])?intval($post['_source']['uploader_source']):0;
			$editor_video 				= isset($post['_source']['editor_video'])?intval($post['_source']['editor_video']):0;
			$uploader 					= isset($post['_source']['uploader'])?intval($post['_source']['uploader']):0;
			$reporter 					= isset($post['_source']['reporter'])?intval($post['_source']['reporter']):0;
			$cameraman 					= isset($post['_source']['cameraman'])?intval($post['_source']['cameraman']):0;
			$source 					= isset($post['_source']['source'])?intval($post['_source']['source']):0;
			$update_date 				= isset($post['_source']['update_date'])?$post['_source']['update_date']:"";
			$publish 					= isset($post['_source']['publish'])?intval($post['_source']['publish']):0;
			$fulltexts 					= isset($post['_source']['fulltexts'])?$post['_source']['fulltexts']:"";
			$publish_date 				= isset($post['_source']['publish_date'])?$post['_source']['publish_date']:"";
			$camera_name 				= isset($post['_source']['camera_name'])?$post['_source']['camera_name']:"";
			$reporter_name 				= isset($post['_source']['reporter_name'])?$post['_source']['reporter_name']:"";
			$editor_video_name 			= isset($post['_source']['editor_video_name'])?$post['_source']['editor_video_name']:"";
			$name_source 				= isset($post['_source']['name_source'])?$post['_source']['name_source']:"";
			$uploader_name 				= isset($post['_source']['uploader_name'])?$post['_source']['uploader_name']:"";
			$host_id 					= isset($post['_source']['host_id'])?$post['_source']['host_id']:"";
			$host_name 					= isset($post['_source']['host_name'])?$post['_source']['host_name']:"";
			$file 						= isset($post['_source']['file'])?$post['_source']['file']:"";
			$upload_date 				= isset($post['_source']['upload_date'])?$post['_source']['upload_date']:"";
			$poster 					= isset($post['_source']['poster'])?$post['_source']['poster']:"";
			$views_count 				= isset($post['_source']['views_count'])?intval($post['_source']['views_count']):0;
			$views 						= isset($post['_source']['views'])?intval($post['_source']['views']):0;
			
			/* echo "<pre>";
			print_r($post);
			echo "</pre>"; */
			
			$arrInsert = array();
			$arrInsert['id'] = $id;
			$arrInsert['title'] = $title;
			$arrInsert['alias'] = $alias;
			$arrInsert['topic'] = $topic;
			$arrInsert['category'] = $category;
			$arrInsert['uploader_source'] = $uploader_source;
			$arrInsert['editor_video'] = $editor_video;
			$arrInsert['uploader'] = $uploader;
			$arrInsert['reporter'] = $reporter;
			$arrInsert['cameraman'] = $cameraman;
			$arrInsert['source'] = $source;
			if(!empty($update_date)) $arrInsert['update_date'] = $update_date;
			$arrInsert['publish'] = $publish;
			$arrInsert['fulltexts'] = $fulltexts;
			$arrInsert['publish_date'] = $publish_date;
			$arrInsert['camera_name'] = $camera_name;
			$arrInsert['reporter_name'] = $reporter_name;
			$arrInsert['editor_video_name'] = $editor_video_name;
			$arrInsert['name_source'] = $name_source;
			$arrInsert['uploader_name'] = $uploader_name;
			$arrInsert['host_id'] = $host_id;
			$arrInsert['host_name'] = $host_name;
			$arrInsert['file'] = $file;
			$arrInsert['upload_date'] = $upload_date;
			$arrInsert['poster'] = $poster;
			$arrInsert['views_count'] = $views_count;
			$arrInsert['views'] = $views;
			
			$responseInsert = $opensearch->insert("tribunnews-video", $arrInsert);
			
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
	if (!empty($lastid)) {
		if (!$handle = fopen($filename, 'w+')) {
			die("Cannot open file $filename");
		}
		if (fwrite($handle, $lastid) === FALSE) {
			die("Cannot write to file $this->log_file");
		}
		
		$loginfo = "TOTAL = ".$totalData." | TOTAL MIGRASI = ".$total." | LAST ID = ".$lastid."\n";
		$writelog->doLogInfo($loginfo);
	}
}

$writelog->closeLog();
unset($opensearch);
unset($elasticsearch);

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>