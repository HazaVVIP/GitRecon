<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

/* 
Running command
- sudo -u cron sudo -u www-data /usr/bin/php7.4 /var/www/html/web-cron/tools/rpt_tribun_fotosouce_article.php
*/

include DOC_ROOT."config/config.php";
include DOC_ROOT."config/other_config.php";
include DOC_ROOT."lib/Opensearch.php";

$dateStart = isset($_GET['start'])?$_GET['start']:"";
$dateEnd = isset($_GET['end'])?$_GET['end']:"";
		
if(empty($dateStart)){	
	$dateStart = date("Y-m-d", strtotime('-1 days'));
}

if(empty($dateEnd)){	
	$dateEnd = date("Y-m-d", strtotime('-1 days'));
}

echo $dateStart." - ".$dateEnd."<br>";

$arrMust = array();
array_push($arrMust,array("range" => array("publish_date" => array("gte" => ''.$dateStart.' 00:00:00', "lte" =>''.$dateEnd.' 23:59:59'))));	
//array_push($arrMust,array("regexp" => array("foto_source.keyword" => ".*(tribun|Tribun|tribunnews|Tribunnews|serambi|Serambi|banjarmasin|Banjarmasin|wartakota|Wartakota|kupang|Kupang|belitung|Belitung|sripoku|Sripoku|surya\\.co\\.id|Surya\\.co\\.id|prohaba|Prohaba).*")));	
array_push($arrMust,array("regexp" => array("foto_source" => ".*(kompas|parapuan|stylo|nova.id|tabloidnova|otomania|geographic|bolasport|sonora|kontan|grid|sajian|intisari|tribun|tribunnews|serambi|bangka|banjarmasin|wartakota|kupang|belitung|sripoku|sriwijaya|suryamalang|surya|prohaba|istimewa).*")));	

$arrMustNot = array();
array_push($arrMustNot,array("term" => array("foto_source.keyword" => "")));	

$query = array("bool" =>
				array(
					"must" => $arrMust,
					"must_not" => $arrMustNot
				)
	);

$opensearchAllNetwork = new Opensearch();
$opensearchAllNetwork->init(OS_ALLNETWOORK_URL,OS_ALLNETWOORK_USERNAME,OS_ALLNETWOORK_PASSWORD,true);

$fields = array('domain','domain_id','alias','publish_date','foto_source');
$start = 0;
$limit = 10000;
$sort = array("publish_date" => array("order" => "asc"));
$response_os_allnetwork = $opensearchAllNetwork->find("tribunnetwork-articles",$query,$fields,$sort,$start,$limit);	

if($response_os_allnetwork['status']){
	$totalOsAllNetwork = isset($response_os_allnetwork['total_row'])?$response_os_allnetwork['total_row']:0;
	$dataOsAllNetwork = isset($response_os_allnetwork['data'])?$response_os_allnetwork['data']:array();
	
	if(count($dataOsAllNetwork) > 0){
		
		echo "Total : ".$totalOsAllNetwork."<hr>";
		$no = 1;
		foreach($dataOsAllNetwork as $rowosallnetwork){
			$row = $rowosallnetwork['_source'];
			
			$foto_source = isset($row['foto_source'])?$row['foto_source']:"";
			$domain = isset($row['domain'])?$row['domain']:"";
			$alias = isset($row['alias'])?$row['alias']:"";
			$publish_date = isset($row['publish_date'])?$row['publish_date']:"";
			$url = "https://".$domain.".tribunnews.com/".$alias;
			if($domain == "tribunnews") $url = "https://www.tribunnews.com/".$alias;
			if($domain == "jatimtimur") $url = "https://jatim-timur.tribunnews.com/".$alias;
				
			//echo $publish_date.",".$foto_source.",".$url,"<br>";
			echo $foto_source.",".$url,"<br>";
			$no++;
		}
	}
}

unset($opensearchAllNetwork);

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>