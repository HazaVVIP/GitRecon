<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

define("DOC_ROOT","/var/www/html/cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";
include DOC_ROOT."lib/Writelog.php";

$daerah = "sultra";
$date = isset($_GET['date'])?$_GET['date']:"";

if(!empty($date)){
	$dateStart = $date;
	$dateEnd = $date;
} else {	
	$dateStart = date("Y-m-d", strtotime('-1 days'));
	$dateEnd = date("Y-m-d", strtotime('-1 days'));
}

echo $daerah."<br>";
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
						'written_date' => 
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
$sort = array("written_date" => "asc");
$start = 0;
$limit = 1000;
	
$elasticsearch = new Opensearch();
$elasticsearch->init(ES_DAERAH_URL,"","",false);
$index = $daerah.".tribundaerah-articles";
$response_es = $elasticsearch->find($index,$condition,$fields,$sort,$start,$limit);
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
$opensearch->init(OS_DAERAH_URL,OS_DAERAH_USERNAME,OS_DAERAH_PASSWORD,true);
$response_os = $opensearch->find($index,$condition,$fields,$sort,$start,$limit);
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

$con = mysqli_connect(RDS_DAERAH_NEW_HOST,RDS_DAERAH_NEW_USERNAME,RDS_DAERAH_NEW_PASSWORD,$daerah);
if (mysqli_connect_errno()) {
	echo "Failed to connect to MySQL: " . mysqli_connect_error();
	exit();
}

$arrID = array();

//if(count($arrIDEs) > 0 && count($arrIDOs) > 0){
	//if($totalEs != $totalOs){
		//$arrID = array_diff($arrIDEs, $arrIDOs);
		$arrID = $arrIDEs; //test
		
		if(count($arrID) > 0){
			foreach($arrID as $sid){
				//echo $sid."<br>";
				$condition = array("match" => array("id" => $sid));
				$response_one = $elasticsearch->findOne($index, $condition);
				
				if($response_one['status']){
					$post = isset($response_one['data'])?$response_one['data']:array();
					
					$id 						= isset($post['_source']['id'])?intval($post['_source']['id']):0;
					$title 						= isset($post['_source']['title'])?$post['_source']['title']:"";
					$alias 						= isset($post['_source']['alias'])?$post['_source']['alias']:"";
					$subtitle 					= isset($post['_source']['subtitle'])?$post['_source']['subtitle']:"";
					$subtitle_alias 			= isset($post['_source']['subtitle_alias'])?$post['_source']['subtitle_alias']:"";
					$foto_type 					= isset($post['_source']['foto_type'])?$post['_source']['foto_type']:"";
					$foto_name 					= isset($post['_source']['foto_name'])?$post['_source']['foto_name']:"";
					$foto_caption 				= isset($post['_source']['foto_caption'])?$post['_source']['foto_caption']:"";
					$foto_position 				= "left";
					$foto_source 				= isset($post['_source']['foto_source'])?$post['_source']['foto_source']:"";
					$introtext 					= isset($post['_source']['introtext'])?$post['_source']['introtext']:"";
					$fulltexts 					= isset($post['_source']['fulltexts'])?$post['_source']['fulltexts']:"";
					$section_id 				= isset($post['_source']['section_id'])?intval($post['_source']['section_id']):0;
					$category_id 				= isset($post['_source']['category_id'])?intval($post['_source']['category_id']):0;
					$publish 					= isset($post['_source']['publish'])?intval($post['_source']['publish']):0;
					$frontpage_section 			= isset($post['_source']['frontpage_section'])?intval($post['_source']['frontpage_section']):0;
					$frontpage_category 		= isset($post['_source']['frontpage_category'])?intval($post['_source']['frontpage_category']):0;
					$written_by 				= isset($post['_source']['written_by'])?intval($post['_source']['written_by']):0;
					$editor_by 					= isset($post['_source']['editor_by'])?intval($post['_source']['editor_by']):0;
					$written_date 				= isset($post['_source']['written_date'])?$post['_source']['written_date']:"";
					$publish_date 				= isset($post['_source']['publish_date'])?$post['_source']['publish_date']:"";
					$source 					= isset($post['_source']['source'])?intval($post['_source']['source']):0;
					$livereport 				= isset($post['_source']['livereport'])?intval($post['_source']['livereport']):0;
					$youtube 					= isset($post['_source']['youtube'])?$post['_source']['youtube']:"";
					$related_id 				= isset($post['_source']['related_id'])?$post['_source']['related_id']:"";
					$editor 					= isset($post['_source']['editor'])?$post['_source']['editor']:"";
					$editor_fullname 			= isset($post['_source']['editor_fullname'])?$post['_source']['editor_fullname']:"";
					$editor_id 					= isset($post['_source']['editor_id'])?intval($post['_source']['editor_id']):0;
					$hit 						= isset($post['_source']['hit'])?intval($post['_source']['hit']):0;
					$section 					= isset($post['_source']['section'])?$post['_source']['section']:"";
					$writter 					= isset($post['_source']['writter'])?$post['_source']['writter']:"";
					$writter_fullname 			= isset($post['_source']['writter_fullname'])?$post['_source']['writter_fullname']:"";
					$writter_id 				= isset($post['_source']['writter_id'])?intval($post['_source']['writter_id']):0;
					$sstatus 					= isset($post['_source']['sstatus'])?intval($post['_source']['sstatus']):0;
					$c_title 					= isset($post['_source']['c_title'])?$post['_source']['c_title']:"";
					$c_alias 					= isset($post['_source']['c_alias'])?$post['_source']['c_alias']:"";
					$s_title 					= isset($post['_source']['s_title'])?$post['_source']['s_title']:"";
					$name_source 				= isset($post['_source']['name_source'])?$post['_source']['name_source']:"";
					$url_source 				= isset($post['_source']['url_source'])?$post['_source']['url_source']:"";
					$quote_by 					= isset($post['_source']['quote_by'])?intval($post['_source']['quote_by']):0;
					$index_year 				= isset($post['_source']['publish_date'])?date("Y",strtotime($post['_source']['publish_date'])):"";
					
					if(empty($s_title)){
						$sqlSection = "SELECT alias, title, status FROM sections WHERE id = ".$section_id;
						$resultSection = mysqli_query($con, $sqlSection);
						$rowSection = mysqli_fetch_array($resultSection, MYSQLI_ASSOC);
						$s_title  = isset($rowSection['title'])?$rowSection['title']:$s_title;
						$section  = isset($rowSection['alias'])?$rowSection['alias']:$section;
						$sstatus  = isset($rowSection['status'])?intval($rowSection['status']):0;
					}
					
					if(empty($c_title)){
						$sqlCategory = "SELECT alias, title FROM categories WHERE id = ".$category_id;
						$resultCategory = mysqli_query($con, $sqlCategory);
						$rowCategory = mysqli_fetch_array($resultCategory, MYSQLI_ASSOC);
						$c_title  = isset($rowCategory['title'])?$rowCategory['title']:$c_title;
						$c_alias  = isset($rowCategory['alias'])?$rowCategory['alias']:$c_alias;
					}
					
					if(empty($name_source)){
						$sqlSource = "SELECT name_source, url_source FROM source_news WHERE id = ".$source;
						$resultSource = mysqli_query($con, $sqlSource);
						$rowSource = mysqli_fetch_array($resultSource, MYSQLI_ASSOC);
						$name_source  = isset($rowSource['name_source'])?$rowSource['name_source']:$name_source;
						$url_source  = isset($rowSource['url_source'])?$rowSource['url_source']:$url_source;
					}
					
					$sqlUsersEditor = "SELECT id, username, fullname FROM users WHERE id = ".$editor_by;
					$resultUsersEditor = mysqli_query($con, $sqlUsersEditor);
					$rowUsersEditor = mysqli_fetch_array($resultUsersEditor, MYSQLI_ASSOC);
					$editor_id  = isset($rowUsersEditor['id'])?intval($rowUsersEditor['id']):$editor_by;
					$editor_fullname  = isset($rowUsersEditor['fullname'])?$rowUsersEditor['fullname']:$editor_fullname;
					$editor  = isset($rowUsersEditor['username'])?$rowUsersEditor['username']:$editor;
					
					$sqlUsersWritter = "SELECT id, username, fullname FROM users WHERE id = ".$written_by;
					$resultUsersWritter = mysqli_query($con, $sqlUsersWritter);
					$rowUsersWritter = mysqli_fetch_array($resultUsersWritter, MYSQLI_ASSOC);
					$writter_id  = isset($rowUsersWritter['id'])?intval($rowUsersWritter['id']):$written_by;
					$writter_fullname  = isset($rowUsersWritter['fullname'])?$rowUsersWritter['fullname']:$writter_fullname;
					$writter_username  = isset($rowUsersWritter['username'])?$rowUsersWritter['username']:"";
					
					/* echo "<pre>";
					print_r($post);
					echo "</pre>"; */
					
					$arrInsert = array();
					$arrInsert['id'] = $id;
					$arrInsert['title'] = $title;
					$arrInsert['alias'] = $alias;
					$arrInsert['subtitle'] = $subtitle;
					$arrInsert['subtitle_alias'] = $subtitle_alias;
					$arrInsert['foto_type'] = $foto_type;
					$arrInsert['foto_name'] = $foto_name;
					$arrInsert['foto_caption'] = $foto_caption;
					$arrInsert['foto_position'] = $foto_position;
					$arrInsert['foto_source'] = $foto_source;
					$arrInsert['introtext'] = $introtext;
					$arrInsert['fulltexts'] = $fulltexts;
					$arrInsert['section_id'] = $section_id;
					$arrInsert['category_id'] = $category_id;
					$arrInsert['publish'] = $publish;
					$arrInsert['frontpage_section'] = $frontpage_section;
					$arrInsert['frontpage_category'] = $frontpage_category;
					$arrInsert['written_by'] = $written_by;
					$arrInsert['editor_by'] = $editor_by;
					$arrInsert['written_date'] = $written_date;
					$arrInsert['publish_date'] = $publish_date;
					$arrInsert['source'] = $source;
					$arrInsert['livereport'] = $livereport;
					$arrInsert['youtube'] = $youtube;
					$arrInsert['related_id'] = $related_id;
					$arrInsert['editor'] = $editor;
					$arrInsert['editor_fullname'] = $editor_fullname;
					$arrInsert['editor_id'] = $editor_id;
					$arrInsert['hit'] = $hit;
					$arrInsert['section'] = $section;
					$arrInsert['writter'] = $writter;
					$arrInsert['writter_username'] = $writter_username;
					$arrInsert['writter_fullname'] = $writter_fullname;
					$arrInsert['writter_id'] = $writter_id;
					$arrInsert['sstatus'] = $sstatus;
					$arrInsert['c_title'] = $c_title;
					$arrInsert['c_alias'] = $c_alias;
					$arrInsert['s_title'] = $s_title;
					$arrInsert['name_source'] = $name_source;
					$arrInsert['url_source'] = $url_source;
					$arrInsert['quote_by'] = $quote_by;
					$arrInsert['index_year'] = $index_year;
					
					$responseInsert = $opensearch->insert($index, $arrInsert);
					
					/* echo "<pre>";
					print_r($responseInsert);
					print_r($arrInsert);
					echo "</pre>"; */
				}	
			}
		}
	//}
//}	
	



mysqli_close($con);
unset($elasticsearch);
unset($opensearch);


echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>