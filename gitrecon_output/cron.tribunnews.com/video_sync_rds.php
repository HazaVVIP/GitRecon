<?php
/* ini_set('display_errors',1);
error_reporting(E_ALL); */
error_reporting(0);
ini_set("memory_limit", "-1");
set_time_limit(0);
		
$time_start = time();
include "config/config.php";
include "lib/Opensearch.php";

$date = isset($_GET['date'])?$_GET['date']:"";

if(!empty($date)){
	$dateStart = $date;
	$dateEnd = $date;
} else {	
	$dateStart = date("Y-m-d", strtotime('-1 days'));
	$dateEnd = date("Y-m-d", strtotime('-1 days'));
}


echo $dateStart." - ".$dateEnd."<br>";

//RDS
$con = mysqli_connect(RDS_HOST,RDS_USERNAME,RDS_PASSWORD,"tribunnews");

if (mysqli_connect_errno()) {
	echo "Failed to connect to MySQL: " . mysqli_connect_error();
	exit();
}

$sql = "SELECT id FROM video 
		WHERE 
		upload_date BETWEEN '".$dateStart." 00:00:00' AND '".$dateEnd." 23:59:59'
		ORDER BY id DESC";
$result = $result = mysqli_query($con, $sql);
$totalRds = mysqli_num_rows($result);

$arrIDRds = array();
if($totalRds > 0){
	while ($row = mysqli_fetch_array($result, MYSQLI_ASSOC)){
		array_push($arrIDRds, $row['id']);
	}
}	

mysqli_free_result($result);



echo "RDS Total : ".$totalRds."<br>";


//OS	
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
$sort = array("id" => "desc");
$start = 0;
$limit = 1000;
$opensearch = new Opensearch();
$opensearch->init(OS_URL,OS_USERNAME,OS_PASSWORD,true);
$response = $opensearch->find('tribunnews-video',$condition,$fields,$sort,$start,$limit);

$totalOs = 0;
$arrIDOs = array();
if($response['status']){
	$totalOs = isset($response['total_row'])?$response['total_row']:0;
	$dataOs = isset($response['data'])?$response['data']:array();
	
	if(count($dataOs) > 0){
		foreach($dataOs as $rowos){
			array_push($arrIDOs, intval($rowos['_source']['id']));
		}
	}
}

echo "OS Total : ".$totalOs."<br>";

/* echo "<pre>";
print_r($arrIDRds);
print_r($arrIDOs);
echo "<pre>"; */

$arrID = array();
$arrID = array_diff($arrIDRds, $arrIDOs);
$totalSyncOs = 0;
		
if(count($arrID) > 0){
	foreach($arrID as $sid){
		//echo $sid."<br>";
		
		$sqlDetail = "SELECT v.*,
				c.fullname as camera_name, r.fullname as reporter_name, ev.fullname as editor_video_name,
				u.fullname as uploader_name, s.name_source as source
				FROM video v
				LEFT JOIN users c on v.cameraman = c.id
				LEFT JOIN users r on v.reporter = r.id
				LEFT JOIN users ev on v.editor_video = ev.id
				LEFT JOIN users u on v.uploader = u.id
				LEFT JOIN source_news s on v.source = s.id
				WHERE 
				v.id = ".$sid;
		$result = mysqli_query($con, $sqlDetail);
		$row = mysqli_fetch_array($result, MYSQLI_ASSOC);
		
		
		$id 						= isset($row['id'])?intval($row['id']):0;
		$title 						= isset($row['title'])?$row['title']:"";
		$alias 						= isset($row['alias'])?$row['alias']:"";
		$topic 						= isset($row['topic'])?$row['topic']:"";
		$topic_alias 				= !empty($topic)?str_replace(" ","-",strtolower($topic)):"";
		$category 					= isset($row['category'])?$row['category']:"";
		$uploader_source 			= isset($row['uploader_source'])?intval($row['uploader_source']):0;
		$editor_video 				= isset($row['editor_video'])?intval($row['editor_video']):0;
		$uploader 					= isset($row['uploader'])?intval($row['uploader']):0;
		$reporter 					= isset($row['reporter'])?intval($row['reporter']):0;
		$cameraman 					= isset($row['cameraman'])?intval($row['cameraman']):0;
		$source 					= isset($row['source'])?intval($row['source']):0;
		$update_date 				= isset($row['update_date'])?$row['update_date']:"";
		$publish 					= isset($row['publish'])?intval($row['publish']):0;
		$fulltexts 					= isset($row['fulltexts'])?$row['fulltexts']:"";
		$publish_date 				= isset($row['publish_date'])?$row['publish_date']:"";
		$camera_name 				= isset($row['camera_name'])?$row['camera_name']:"";
		$reporter_name 				= isset($row['reporter_name'])?$row['reporter_name']:"";
		$editor_video_name 			= isset($row['editor_video_name'])?$row['editor_video_name']:"";
		$uploader_name 				= isset($row['uploader_name'])?$row['uploader_name']:"";
		$name_source 				= isset($row['name_source'])?$row['name_source']:"";
		$host_id 					= isset($row['host_id'])?$row['host_id']:0;
		$host_name 					= isset($row['host_name'])?$row['host_name']:0;
		$file 						= isset($row['file'])?$row['file']:"";
		$upload_date 				= isset($row['upload_date'])?$row['upload_date']:"";
		$poster 					= isset($row['poster'])?$row['poster']:"";
		$views_count 				= 0;
		$views 						= isset($row['views'])?intval($row['views']):0;
		
		if(!mb_check_encoding($title, 'UTF-8')){
			$title = mb_convert_encoding ($title, 'UTF-8');
			$title = str_replace("?","",$title);
		}
		if(!mb_check_encoding($topic, 'UTF-8')){
			$topic = mb_convert_encoding ($topic, 'UTF-8');
			$topic = str_replace("?"," ",$topic);
		}
		if(!mb_check_encoding($fulltexts, 'UTF-8')){
			$fulltexts = mb_convert_encoding ($fulltexts, 'UTF-8');
		}
		
		$sqlRow = "SELECT c.id as tagging_id, c.title as tagging_title, c.alias as tagging_alias
		FROM video a
		LEFT JOIN tag_related b ON a.id = b.related_id
		LEFT JOIN tag c ON b.tag_id = c.id
		WHERE a.id = ".$id." AND b.related_type = 'video'";
		$resultRow = mysqli_query($con, $sqlRow);
		
		$arrTaging = array();
		while($post = mysqli_fetch_array($resultRow, MYSQLI_ASSOC))
		{
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
		
		$arrInsert = array();
		$arrInsert['id'] = $id;
		$arrInsert['title'] = $title;
		$arrInsert['alias'] = $alias;
		$arrInsert['topic'] = $topic;
		$arrInsert['topic_alias'] = $topic_alias;
		$arrInsert['category'] = $category;
		$arrInsert['uploader_source'] = $uploader_source;
		$arrInsert['editor_video'] = $editor_video;
		$arrInsert['uploader'] = $uploader;
		$arrInsert['reporter'] = $reporter;
		$arrInsert['cameraman'] = $cameraman;
		$arrInsert['source'] = $source;
		if(!empty($update_date) && $update_date != "0000-00-00 00:00:00") $arrInsert['update_date'] = $update_date;
		$arrInsert['publish'] = $publish;
		$arrInsert['fulltexts'] = $fulltexts;
		$arrInsert['publish_date'] = $publish_date;
		$arrInsert['camera_name'] = $camera_name;
		$arrInsert['reporter_name'] = $reporter_name;
		$arrInsert['editor_video_name'] = $editor_video_name;
		$arrInsert['uploader_name'] = $uploader_name;
		$arrInsert['name_source'] = $name_source;
		$arrInsert['host_id'] = $host_id;
		$arrInsert['host_name'] = $host_name;
		$arrInsert['file'] = $file;
		$arrInsert['upload_date'] = $upload_date;
		$arrInsert['poster'] = $poster;
		$arrInsert['views_count'] = $views_count;
		$arrInsert['views'] = $views;
		if(count($arrTaging) > 0){
			$arrInsert['tagging'] = $arrTaging;
		}
		
		$responseInsertOs = $opensearch->insert("tribunnews-video", $arrInsert);
		
		/* echo "<pre>";
		print_r($responseInsertOs);
		print_r($arrInsert);
		echo "</pre>"; */
		
		if($responseInsertOs['status']){
			$totalSyncOs++; 
		}
	}
}
		

echo "Total SYNC RDS ke OS : ".$totalSyncOs."<br>";

mysqli_close($con);

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>