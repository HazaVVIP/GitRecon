<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
//error_reporting(0);
ini_set("memory_limit", "-1");
set_time_limit(0);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."config/other_config.php";
include DOC_ROOT."lib/Opensearch.php";

$site = isset($_GET['site'])?$_GET['site']:"all";
$year = isset($_GET['year'])?$_GET['year']:date("Y");
$isValidDate = validateDate($year,"Y");

if($isValidDate){
	$dateStart = $year."-01-01 00:00:00";
	$dateEnd = $year."-12-31 23:59:59";


	$opensearchReport = new Opensearch();
	$opensearchReport->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

	$index_name = "rpt_rekap_kanal_tribunnews";
	
	if($site == "all"){
		$query =  array(
					"bool" => array(
						"must" => 
							array(
								array(
									"range" => array(
										"dt" => array (
										  'gte' => ''.$dateStart.'',
										  'lte' => ''.$dateEnd.'',
										)
									)
								)
							)
					)
				  );
	} else {
		$query =  array(
					"bool" => array(
						"must" => 
							array(
								array(
									"range" => array(
										"dt" => array (
										  'gte' => ''.$dateStart.'',
										  'lte' => ''.$dateEnd.'',
										)
									)
								),
								array(
									"match_phrase" => array(
										"domain" => ''.$site.''
									)
								)
							)
					)
				  );
	}
				  

	$aggs = array(
				"date_hist_agg" => array(
						"date_histogram" => array(
									"field" => "dt",
									"interval" => "month",
									"format" => "yyyy-MM",
									"order" => array("_term"=> "asc"),
									"min_doc_count" => 1
								   ),
								   "aggs" => array(
										"group_by_section_alias" => array(
											"terms" => array(
												"field" => "section_alias",
												"size" => 1000
											),
											"aggs" => array(
													"total_article" => array(
														"sum" => array(
															"field" => "section_total",
														)
													)
											   )
										)
								   )
					)
				);
	
	$response = $opensearchReport->aggregations($index_name,$aggs,$query);

	if($response['status']){
		$rows = isset($response['data']['date_hist_agg']['buckets'])?$response['data']['date_hist_agg']['buckets']:array();
		
		if(count($rows) > 0){
			
			echo $site."<br>";
			
			foreach($rows as $idx => $row){
				$tgl = isset($row['key_as_string'])?$row['key_as_string']:"";
				$datas = isset($row['group_by_section_alias']['buckets'])?$row['group_by_section_alias']['buckets']:array();
				
				echo "<b>".$tgl."</b><br>";
				
				if(count($datas) > 0){
					
					foreach($datas as $iii => $data){
						$section_alias = isset($data['key'])?$data['key']:"";
						$total_article = isset($data['total_article']['value'])?intval($data['total_article']['value']):0;
						
						echo $section_alias.",".$total_article."<br>";
					}
					
					echo "<hr>";
				}
			}
		}
	}	
	
	unset($opensearchReport);
}
function validateDate($date, $format = 'Y-m-d') {
    $d = DateTime::createFromFormat($format, $date);
    return $d && $d->format($format) === $date;
}

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>