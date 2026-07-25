<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();
include "config/config.php";
include "lib/Opensearch.php";
include "lib/Writelog.php";

$dateStart = isset($_GET['start'])?$_GET['start']:"";
$dateEnd = isset($_GET['end'])?$_GET['end']:"";

if(empty($dateStart)){	
	$dateStart = date("Y-m-d", strtotime('-1 days'));
}

if(empty($dateEnd)){	
	$dateEnd = date("Y-m-d", strtotime('-1 days'));
}

echo $dateStart." - ".$dateEnd."<br>";


$condition 	= array (
				'bool' => 
				array (
				  'filter' => 
				  array (
					0 => 
					array (
					  'range' => 
					  array (
						'upload_date' => 
						array (
						  'gte' => ''.$dateStart.' 00:00:00',
						  'lte' => ''.$dateEnd.' 23:59:59',
						),
					  ),
					),
				  ),
				),
			  );	
$fields = array('id');
$sort = array("upload_date" => "asc");
$start = 0;
$limit = 1000;

$elasticsearch = new Opensearch();
$elasticsearch->init(ES_URL,"","",false);
$response_es = $elasticsearch->find('tribunnews-video',$condition,$fields,$sort,$start,$limit);
$totalEs = 0;
$arrIDEs = array();
if($response_es['status']){
	$totalEs = isset($response_es['total_row'])?$response_es['total_row']:0;
	$dataEs = isset($response_es['data'])?$response_es['data']:array();
	
	if(count($dataEs) > 0){
		foreach($dataEs as $rowes){
			array_push($arrIDEs, intval($rowes['_source']['id']));
		}
	}
}



$opensearch = new Opensearch();
$opensearch->init(OS_URL,OS_USERNAME,OS_PASSWORD,true);
$response_os = $opensearch->find('tribunnews-video',$condition,$fields,$sort,$start,$limit);
$totalOs = 0;
$arrIDOs = array();
if($response_os['status']){
	$totalOs = isset($response_os['total_row'])?$response_os['total_row']:0;
	$dataOs = isset($response_os['data'])?$response_os['data']:array();
	
	if(count($dataOs) > 0){
		foreach($dataOs as $rowos){
			array_push($arrIDOs, intval($rowos['_source']['id']));
		}
	}
}


echo "Total ES : ".$totalEs."<br>";
echo "Total OS : ".$totalOs."<br>";

/* echo "<pre>";
print_r($arrIDEs);
print_r($arrIDOs);
echo "<pre>"; */

$arrID = array();

//if(count($arrIDEs) > 0 && count($arrIDOs) > 0){
	if($totalEs != $totalOs){
		$arrID = array_diff($arrIDEs, $arrIDOs);
		
		if(count($arrID) > 0){
			echo "<pre>";
			print_r($arrID);
			echo "<pre>";
		}
	}
//}	

unset($elasticsearch);
unset($opensearch);


echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>