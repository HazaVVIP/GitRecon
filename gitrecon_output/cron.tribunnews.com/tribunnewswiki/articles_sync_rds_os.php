<?php
/* ini_set('display_errors',1);
error_reporting(E_ALL); */
error_reporting(0);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

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
$opensearch->init(OS_TNEWSWIKI_URL,OS_TNEWSWIKI_USERNAME,OS_TNEWSWIKI_PASSWORD,true);
$response_os = $opensearch->find('tribunnewswiki-articles',$condition,$fields,$sort,$start,$limit);
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
$conTnews = mysqli_connect(RDS_HOST,RDS_USERNAME,RDS_PASSWORD,"tribunnews");
if (mysqli_connect_errno()) {
	echo "Failed to connect to MySQL: " . mysqli_connect_error();
	exit();
}

$con = mysqli_connect(RDS_TNEWSWIKI_HOST,RDS_TNEWSWIKI_USERNAME,RDS_TNEWSWIKI_PASSWORD,"tribunnews");
if (mysqli_connect_errno()) {
	echo "Failed to connect to MySQL: " . mysqli_connect_error();
	exit();
}


$totalRds = 0;
$arrIDRds = array();
$sql = "SELECT a.id
		FROM articles a
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
$arrID = array_diff($arrIDRds, $arrIDOs);
$arrIDWrong = array_diff($arrIDOs, $arrIDRds);
$totalSyncOs = 0;

/* echo "<pre>";
print_r($arrIDWrong);
echo "</pre>"; */

if(count($arrID) > 0){
	foreach($arrID as $id){
		$sqlRow = "SELECT a.id, a.title, a.alias, a.alias_old, a.subtitle, a.foto_type, a.foto_name, a.foto_caption, a.wikiblog, a.foto_source,
			a.introtext, a.fulltexts, a.publish, a.frontpage_section, a.frontpage_category,
			a.editor_by, a.written_by, a.written_date, a.publish_date, a.source, a.livereport, a.youtube
			FROM articles a
	    WHERE a.id = ".$id;
		$resultRow = mysqli_query($con, $sqlRow);
		$post = mysqli_fetch_array($resultRow, MYSQLI_ASSOC);
		
		$id 						= isset($post['id'])?intval($post['id']):0;
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
		$editor_by 					= isset($post['editor_by'])?intval($post['editor_by']):0;
		$written_date 				= isset($post['written_date'])?$post['written_date']:"";
		$publish_date 				= isset($post['publish_date'])?$post['publish_date']:"";
		$youtube 					= isset($post['youtube'])?$post['youtube']:"";
		$hit 						= isset($post['hit'])?intval($post['hit']):0;
		$index_year 				= isset($post['publish_date'])?date("Y",strtotime($post['publish_date'])):"";
		
		if(!mb_check_encoding($title, 'UTF-8')){
			$title = mb_convert_encoding ($title, 'UTF-8');
			$title = str_replace("?","",$title);
		}
		if(!mb_check_encoding($subtitle, 'UTF-8')){
			$subtitle = mb_convert_encoding ($subtitle, 'UTF-8');
			$subtitle = str_replace("?"," ",$subtitle);
		}		
		if(!mb_check_encoding($introtext, 'UTF-8')){
			$introtext = mb_convert_encoding ($introtext, 'UTF-8');
			$introtext = str_replace("?","",$introtext);
		}
		if(!mb_check_encoding($foto_caption, 'UTF-8')){
			$foto_caption = mb_convert_encoding ($foto_caption, 'UTF-8');
			$foto_caption = str_replace("?","",$foto_caption);
		}
		if(!mb_check_encoding($foto_source, 'UTF-8')){
			$foto_source = mb_convert_encoding ($foto_source, 'UTF-8');
			$foto_source = str_replace("?","",$foto_source);
		}
		if(!mb_check_encoding($fulltexts, 'UTF-8')){
			$fulltexts = mb_convert_encoding ($fulltexts, 'UTF-8');
		}
		
		$writter_fullname = "";
		if(!empty($written_by)){
			$sqlRowWritten = "SELECT fullname from users WHERE id = ".$written_by;
			$resultRowWritten = mysqli_query($conTnews, $sqlRowWritten);
			$userWritten = mysqli_fetch_array($resultRowWritten);
			
			$writter_fullname 	= isset($userWritten['fullname'])?$userWritten['fullname']:"";
		}
		
		$editor_fullname = "";
		if(!empty($editor_by)){
			$sqlRowEditor = "SELECT fullname from users WHERE id = ".$editor_by;
			$resultRowEditor = mysqli_query($conTnews, $sqlRowEditor);
			$userEditor = mysqli_fetch_array($resultRowEditor);
			
			$editor_fullname 	= isset($userEditor['fullname'])?$userEditor['fullname']:"";
		}
		
		$sqlRow = "SELECT c.id as tagging_id, c.title as tagging_title, c.alias as tagging_alias
		FROM articles a
		LEFT JOIN tag_related b ON a.id = b.related_id
		LEFT JOIN tag c ON b.tag_id = c.id
	    WHERE a.id = ".$id." AND b.related_type = 'articles'";
		$resultRow = mysqli_query($con, $sqlRow);
		
		$arrTaging = array();
		while($post = mysqli_fetch_array($resultRow, MYSQLI_ASSOC))
		{
			$tagging_title = isset($post['tagging_title'])?$post['tagging_title']:"";
			if(!mb_check_encoding($tagging_title, 'UTF-8')){
				$tagging_title = mb_convert_encoding ($tagging_title, 'UTF-8');
				$tagging_title = str_replace("?","",$tagging_title);
			}
			
			$tagging_alias = isset($post['tagging_alias'])?$post['tagging_alias']:"";
			if(!mb_check_encoding($tagging_alias, 'UTF-8')){
				$tagging_alias = mb_convert_encoding ($tagging_alias, 'UTF-8');
				$tagging_alias = str_replace("?","",$tagging_alias);
			}
			
			$arrTag = array();
			$arrTag['id'] = intval($post['tagging_id']);
			$arrTag['title'] = $tagging_title;
			$arrTag['alias'] = $tagging_alias;
			
			array_push($arrTaging, $arrTag);
		}
		
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
		
		$responseInsertOs = $opensearch->insert("tribunnewswiki-articles", $arrInsert);
					
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

mysqli_free_result($result);
mysqli_close($con);
mysqli_close($conTnews);
unset($opensearch);


echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>