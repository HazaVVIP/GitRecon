<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");
//define("DOC_ROOT",$_SERVER["DOCUMENT_ROOT"]."/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";
include DOC_ROOT."lib/Writelog.php";

$date = isset($_GET['date'])?$_GET['date']:"";

if(!empty($date)){
	$dateStart = $date;
	$dateEnd = $date;
} else {	
	$dateStart = date("Y-m-d", strtotime('-1 days'));
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
						'publish_date' => 
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
$sort = array("publish_date" => "asc");
$start = 0;
$limit = 1000;

//OS
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

echo "Total OS : ".$totalOs."<br>";

//RDS
$con = mysqli_connect(RDS_HOST,RDS_USERNAME,RDS_PASSWORD,"tribunnews");
if (mysqli_connect_errno()) {
	echo "Failed to connect to MySQL: " . mysqli_connect_error();
	exit();
}


$totalRds = 0;
$arrIDRds = array();
$sql = "SELECT a.id
		FROM video a
	    WHERE a.publish_date BETWEEN '".$dateStart." 00:00:00' AND '".$dateEnd." 23:59:59'
	    ORDER BY a.id DESC";
$result = mysqli_query($con, $sql);
$totalRds = mysqli_num_rows($result);

if($totalRds > 0){
	while($post = mysqli_fetch_assoc($result))
	{
		array_push($arrIDRds, intval($post['id']));
	}	
}

echo "Total RDS : ".$totalRds."<br>";

$arrID = array();
//$arrID = array_diff($arrIDRds, $arrIDOs);
$arrID = $arrIDRds;
$totalSyncOs = 0;

if(count($arrID) > 0){
	foreach($arrID as $id){
		$sqlRow = "SELECT a.topic, c.id as tagging_id, c.title as tagging_title, c.alias as tagging_alias
		FROM video a
		LEFT JOIN tag_related b ON a.id = b.related_id
		LEFT JOIN tag c ON b.tag_id = c.id
	    WHERE a.id = ".$id." AND b.related_type = 'video'";
		$resultRow = mysqli_query($con, $sqlRow);

		$arrTaging = array();
		$topic = "";
		$topic_alias = "";
		while($post = mysqli_fetch_array($resultRow, MYSQLI_ASSOC))
		{
			$topic 		= isset($post['topic'])?$post['topic']:"";
			if(!mb_check_encoding($topic, 'UTF-8')){
				$topic = mb_convert_encoding ($topic, 'UTF-8');
				$topic = str_replace("?"," ",$topic);
			}
			$topic_alias = !empty($topic)?str_replace(" ","-",strtolower($topic)):"";
			
			$tagging_title = isset($post['tagging_title'])?$post['tagging_title']:"";
			if(!mb_check_encoding($tagging_title, 'UTF-8')){
				$tagging_title = mb_convert_encoding ($tagging_title, 'UTF-8');
				$tagging_title = str_replace("?","",$tagging_title);
			}
			
			$arrTag = array();
			$arrTag['id'] = intval($post['tagging_id']);
			$arrTag['title'] = $tagging_title;
			$arrTag['alias'] = $post['tagging_alias'];
			
			array_push($arrTaging, $arrTag);
		}
		
		if(count($arrTaging) > 0){
			$dataUpdateOS = array();
			$dataUpdateOS['topic'] = $topic;
			$dataUpdateOS['topic_alias'] = $topic_alias;
			$dataUpdateOS['tagging'] = $arrTaging;
			
			$responseUpdateOs = $opensearch->updateOne('tribunnews-video',$id,$dataUpdateOS);
			
			if($responseUpdateOs['status'] == 1){
				$totalSyncOs++; 
			} else {
				echo "<pre>";
				echo $id."<br>";
				print_r($responseUpdateOs);
				print_r($dataUpdateOS);
				echo "</pre>";
			}
		}	
	}
}

echo "Total SYNC RDS ke OS : ".$totalSyncOs."<br>";

mysqli_free_result($result);
mysqli_close($con);
unset($opensearch);


echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>