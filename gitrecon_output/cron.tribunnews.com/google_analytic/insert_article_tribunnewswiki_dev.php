<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
//error_reporting(0);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

require_once "vendor_new/autoload.php";
include DOC_ROOT."config/config.php";
include DOC_ROOT."config/other_config.php";
include DOC_ROOT."lib/Opensearch.php";
include DOC_ROOT."lib/Google_analytic4.php";

define("AUTH_CREDENTIAL_PROD", DOC_ROOT."google_analytic/tribunnews-17d8f@appspot.gserviceaccount.json");
define("AUTH_CREDENTIAL_STAG", DOC_ROOT."google_analytic/google-analytic-dev@stone-goal-266105.iam.gserviceaccount.json");

/* 
Running in command
- sudo -u cron /usr/bin/php7.4 /var/www/html/web-cron/google_analytic/insert_article_tribunnewswiki.php > /home/cron/log_cron/insert_ga_article_tribunnewswiki.txt
*/

$google_analytic = new Google_analytic4(AUTH_CREDENTIAL_PROD);

$propertyId = '280294341'; //tribunnews all network
$google_analytic->initializeAnalytics($propertyId);
$analytics = $google_analytic->getReportTopArticleTribunnewsWiki();

$dataPopuler = array();
$total = 0;

if($analytics['status']){
	$dataPopuler = isset($analytics['data'])?$analytics['data']:array();
	
	if(count($dataPopuler) > 0){
		$opensearchTest = new Opensearch();
		$opensearchTest->init(OS_DEV_URL,OS_DEV_USERNAME,OS_DEV_PASSWORD,true);
		
		$opensearchWiki = new Opensearch();
		$opensearchWiki->init(OS_TNEWSWIKI_URL,OS_TNEWSWIKI_USERNAME,OS_TNEWSWIKI_PASSWORD,true);
		
		//Reset Rank
		$condition 	= array("terms" => array("rank" => array(1,2,3,4,5,6,7,8,9,10)));	
		$fields 	= array("title", "rank");
		$sort 		= array("rank" => array("order" => "asc"));
		$response1 	= $opensearchWiki->find("tribunnewswiki-populer-ga-articles", $condition, $fields, $sort);
		//$response1 	= $opensearchTest->find("tribunnewswiki-populer-ga-articles", $condition, $fields, $sort);
		
		$totalRank = 0;
		if($response1['status']){
			$id = isset($response1['data'])?$response1['data']:array();
					
			if(count($id) > 0){
				$newrank = 21;

				foreach($id as $value){
					$idx 	= isset($value['_id'])?intval($value['_id']):0;
					$rank 	= isset($value['_source']['rank'])?$value['_source']['rank']:21;

					$data = array(
						'rank' => $newrank
					 );
					
					//$response2 	= $opensearchWiki->updateOne("tribunnewswiki-populer-ga-articles", $idx, $data);
					//$response2 	= $opensearchTest->updateOne("tribunnewswiki-populer-ga-articles", $idx, $data);

					//if($response2['status']){
						$totalRank++;
						$newrank++;
					//} 
				}	
			}
		}
		
		//Delete
		$dateToday = date("Y-m-d"); 
		$date2DaysAgo = strtotime('-30 day', strtotime($dateToday));
		$startDate2DaysAgo = date('Y-m-d 00:00:00', $date2DaysAgo);
		$endDate2DaysAgo = date('Y-m-d 23:59:59', $date2DaysAgo);
		$condition = array("range" => array("publish_date" => array("gte" => $startDate2DaysAgo, "lte" => $endDate2DaysAgo)));
		//$response3 = $opensearchWiki->deleteMany("tribunnewswiki-populer-ga-articles",$condition);
		//$response3 = $opensearchTest->deleteMany("tribunnewswiki-populer-ga-articles",$condition);
		
		//Insert
		$total = 0;
		$rank = 1;
		$fields = array("title", "alias", "c_alias", "foto_type", "foto_name", "publish_date", "written_date", "introtext", "wikiblog", "editor_by", "editor_fullname", "written_by", "writter_fullname");
		
		foreach($dataPopuler as $val){
			$id = intval($val['id']);
			$pageviews = intval($val['pageviews']);
			
			$query = array("match" => array("_id" => $id));
			$response4 = $opensearchWiki->findOne("tribunnewswiki-articles", $query, $fields);
			
			if($response4['status']){
				$value = isset($response4['data'])?$response4['data']:array();
				
				$id 				= isset($value['_id'])?(int)$value['_id']:0;
				$title 				= isset($value['_source']['title'])?$value['_source']['title']:"";
				$alias 				= isset($value['_source']['alias'])?$value['_source']['alias']:"";
				$publish_date 		= isset($value['_source']['publish_date'])?$value['_source']['publish_date']:"";
				$foto_type 			= isset($value['_source']['foto_type'])?$value['_source']['foto_type']:"";
				$foto_name 			= isset($value['_source']['foto_name'])?$value['_source']['foto_name']:"";
				$written_date 		= isset($value['_source']['written_date'])?$value['_source']['written_date']:"";
				$introtext 			= isset($value['_source']['introtext'])?$value['_source']['introtext']:"";
				$wikiblog 			= isset($value['_source']['wikiblog'])?$value['_source']['wikiblog']:2;
				$editor_by 			= isset($value['_source']['editor_by'])?(int)$value['_source']['editor_by']:0;
				$editor_fullname 	= isset($value['_source']['editor_fullname'])?$value['_source']['editor_fullname']:"";
				$written_by 		= isset($value['_source']['written_by'])?(int)$value['_source']['written_by']:0;
				$writter_fullname 	= isset($value['_source']['writter_fullname'])?$value['_source']['writter_fullname']:"";
				
				$arrPopuler = array();
				$arrPopuler['id'] = $id;
				$arrPopuler['title'] = strip_tags($title);
				$arrPopuler['rank'] = $rank;
				$arrPopuler['alias'] = strip_tags($alias);
				$arrPopuler['publish_date'] = $publish_date;
				$arrPopuler['foto_type'] = $foto_type;
				$arrPopuler['foto_name'] = strip_tags($foto_name);
				$arrPopuler['written_date'] = $written_date;
				$arrPopuler['introtext'] = strip_tags($introtext);
				$arrPopuler['wikiblog'] = $wikiblog;
				$arrPopuler['editor_by'] = $editor_by;
				$arrPopuler['editor_fullname'] = $editor_fullname;
				$arrPopuler['written_by'] = $written_by;
				$arrPopuler['writter_fullname'] = $writter_fullname;
				$arrPopuler['pageviews'] = $pageviews;
				
				//$responseInsert = $opensearchWiki->insert("tribunnewswiki-populer-ga-articles", $arrPopuler);
				$responseInsert = $opensearchTest->insert("tribunnewswiki-populer-ga-articles", $arrPopuler);
				
				/* echo "<pre>";
				print_r($responseInsert);
				print_r($arrPopuler);
				echo "</pre>"; */
				
				if($responseInsert['status']){
					$total++;
					$rank++;
				}
			}	
		}
		
		unset($opensearchWiki);
		unset($opensearchTest);
	}
}

echo "Total : ".$total."\n";

echo "\nExecution time in seconds: ". (microtime(true) - $time_start) . "\n";
?>