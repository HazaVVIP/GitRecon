<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

/* 
Running in cmd / command
- sudo -u www-data /usr/bin/php7.4 /var/www/html/web-cron/tribunnewswiki/articles_migrasi_os.php
*/

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";
include DOC_ROOT."lib/Writelog.php";

$writelog = new Writelog();
$writelog->Log(PATH_ROOT."/logs/","tribunnewswiki-articles");

$lastid = 0;
$total = 0;
$filename_cached = PATH_ROOT . "/data/lastid_articles_wiki.txt";
$valueLog = file_get_contents($filename_cached);
if ($valueLog !== FALSE) {
	$lastid = $valueLog;
}

//OS
$opensearch = new Opensearch();
$opensearch->init(OS_TNEWSWIKI_URL,OS_TNEWSWIKI_USERNAME,OS_TNEWSWIKI_PASSWORD,true);

$totalOs = 0;
$condition = array("match_all"=>new stdClass);
$response_total = $opensearch->count_total("tribunnewswiki-articles",$condition);
if($response_total['status']){
	$totalOs = isset($response_total['total'])?$response_total['total']:0;
}

$opensearchTBO = new Opensearch();
$opensearchTBO->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$response_totalTBO = $opensearchTBO->count_total('tribunnewswiki-articles',$condition);

$limit = 500;
$sort = array("publish_date" => array("order" => "asc"));
$totalOsTBO = 0;
if($response_totalTBO['status']){
	$totalOsTBO = isset($response_totalTBO['total'])?$response_totalTBO['total']:0;
}

if (empty($lastid)) {
	$query = array();

	$fields = array();
	$response = $opensearch->find("tribunnewswiki-articles",$query,$fields,$sort,0,$limit);	
} else {
	$arrMust = array();
	array_push($arrMust,array("range" => array("id" => array("gt" => $lastid))));
	
	$query = array("bool" =>
				array(
					"must" => $arrMust
				)
	);

	$fields = array();
	$response = $opensearch->find("tribunnewswiki-articles",$query,$fields,$sort,0,$limit);	
}	

$totalSyncOs = 0;
if($response['status']){
	$total = isset($response['total_row'])?$response['total_row']:0;
	
	if($total > 0){
		$arrPosts = isset($response['data'])?$response['data']:array();
		
		foreach($arrPosts as $idx => $posts){
			$post = isset($posts['_source'])?$posts['_source']:array();
			
			if(count($post) > 0){
				$id 						= isset($post['id'])?intval($post['id']):0;
				
				if(!empty($id)){	
					$title 						= isset($post['title'])?$post['title']:"";
					$alias 						= isset($post['alias'])?$post['alias']:"";
					$subtitle 					= isset($post['subtitle'])?$post['subtitle']:"";
					$subtitle_alias 			= !empty($subtitle)?str_replace(" ","-",strtolower($subtitle)):"";
					$foto_type 					= isset($post['foto_type'])?$post['foto_type']:"";
					$foto_name 					= isset($post['foto_name'])?$post['foto_name']:"";
					$foto_caption 				= isset($post['foto_caption'])?$post['foto_caption']:"";
					$foto_source 				= isset($post['foto_source'])?$post['foto_source']:"";
					$introtext 					= isset($post['introtext'])?$post['introtext']:"";
					$fulltexts 					= isset($post['fulltexts'])?$post['fulltexts']:"";
					$wikiblog 					= isset($post['wikiblog'])?intval($post['wikiblog']):2;
					$publish 					= isset($post['publish'])?intval($post['publish']):0;
					$frontpage_section 			= isset($post['frontpage_section'])?intval($post['frontpage_section']):0;
					$frontpage_category 		= isset($post['frontpage_category'])?intval($post['frontpage_category']):0;
					$written_by 				= isset($post['written_by'])?intval($post['written_by']):0;
					$writter_fullname 			= isset($post['writter_fullname'])?$post['writter_fullname']:"";
					$editor_by 					= isset($post['editor_by'])?intval($post['editor_by']):0;
					$editor_fullname 			= isset($post['editor_fullname'])?$post['editor_fullname']:"";
					$written_date 				= isset($post['written_date'])?$post['written_date']:"";
					$publish_date 				= isset($post['publish_date'])?$post['publish_date']:"";
					$youtube 					= isset($post['youtube'])?$post['youtube']:"";
					$hit 						= isset($post['hit'])?intval($post['hit']):0;
					$pageviews 					= isset($post['pageviews'])?intval($post['pageviews']):0;
					$arrTaging 					= isset($post['tagging'])?$post['tagging']:array();
					$index_year 				= isset($post['publish_date'])?date("Y",strtotime($post['publish_date'])):"";
					
					$arrInsert = array();
					$arrInsert['id'] = $id;
					$arrInsert['title'] = $title;
					$arrInsert['alias'] = $alias;
					$arrInsert['subtitle'] = $subtitle;
					$arrInsert['subtitle_alias'] = $subtitle_alias;
					$arrInsert['foto_type'] = $foto_type;
					$arrInsert['foto_name'] = $foto_name;
					$arrInsert['foto_caption'] = $foto_caption;
					$arrInsert['foto_source'] = $foto_source;
					$arrInsert['introtext'] = $introtext;
					$arrInsert['fulltexts'] = $fulltexts;
					$arrInsert['wikiblog'] = $wikiblog;
					$arrInsert['publish'] = $publish;
					$arrInsert['frontpage_section'] = $frontpage_section;
					$arrInsert['frontpage_category'] = $frontpage_category;
					$arrInsert['written_by'] = $written_by;
					$arrInsert['writter_fullname'] = $writter_fullname;
					$arrInsert['editor_by'] = $editor_by;
					$arrInsert['editor_fullname'] = $editor_fullname;
					$arrInsert['written_date'] = $written_date;
					$arrInsert['publish_date'] = $publish_date;
					$arrInsert['youtube'] = $youtube;
					$arrInsert['hit'] = $hit;
					if(count($arrTaging) > 0){
						$arrInsert['tagging'] = $arrTaging;
					}
					$arrInsert['index_year'] = $index_year;
			
					/* echo "<pre>";
					print_r($arrInsert);
					echo "</pre>"; */
					
					$responseInsertOs = $opensearchTBO->insert("tribunnewswiki-articles", $arrInsert);
			
					if($responseInsertOs['status']){
						$totalSyncOs++; 
					} else {
						echo "<pre>";
						print_r($responseInsertOs);
						print_r($arrInsert);
						echo "</pre>";
					}
					
					$lastid = $id;
				}	
			}
		}	
	}
}	

echo "Total OS Tnewswiki : " . $totalOs . "\n";
echo "Total OS VPC TBO : " . $totalOsTBO . "\n";
echo "TOTAL MIGRASI : " . $totalSyncOs . "\n";
echo "LAST ID : " . $lastid . "\n";
if (!empty($lastid)) {
	if (!$handle = fopen($filename_cached, 'w+')) {
		die("Cannot open file $filename_cached");
	}
	if (fwrite($handle, $lastid) === FALSE) {
		die("Cannot write to file $this->log_file");
	}
	
	$loginfo = "Total OS Tnewswiki = ".$totalOs." | Total OS VPC TBO  = ".$totalOsTBO." | TOTAL MIGRASI = ".$totalOsTBO." | LAST ID = ".$lastid."\n";
	$writelog->doLogInfo($loginfo);
}

unset($opensearch);	
unset($opensearchTBO);	

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>