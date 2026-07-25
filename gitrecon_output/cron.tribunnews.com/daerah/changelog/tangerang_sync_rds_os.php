<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$daerah = "tangerang";
$date = isset($_GET['date'])?$_GET['date']:"";

if(!empty($daerah)){
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
		
	
	//RDS
	$con = mysqli_connect(RDS_DAERAH_NEW_HOST,RDS_DAERAH_NEW_USERNAME,RDS_DAERAH_NEW_PASSWORD,$daerah);
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
	
	//OS
	$opensearch = new Opensearch();
	$index = $daerah.".tribundaerah-articles";
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

	echo "Total OS : ".$totalOs."<br>";
	
	$arrID = array();
	$arrID = array_diff($arrIDRds, $arrIDOs);
	$totalSyncOs = 0;

	/* echo "<pre>";
	print_r($arrID);
	echo "</pre>"; */
	
	if(count($arrID) > 0){
		foreach($arrID as $id){
			$sqlRow = "SELECT a.id, a.title, a.alias, a.subtitle, a.foto_type, a.foto_name, a.foto_caption, a.foto_source,
			a.introtext, a.fulltexts, a.section_id, a.category_id, a.publish, a.frontpage_section, a.frontpage_category,
			a.editor_by, a.written_by, a.written_date, a.publish_date, a.source, a.youtube,
			a.related_id, a.quote, a.quote_by, 
			b.username as editor, b.fullname as editor_fullname,
			c.username as writter, c.fullname as writter_fullname,
			d.alias as section, d.title as s_title, d.status as sstatus,
			e.alias as c_alias, e.title as c_title,
			f.name_source, f.url_source
			FROM articles a
			LEFT JOIN users b ON a.editor_by = b.id
			LEFT JOIN users c ON a.written_by = c.id
			LEFT JOIN sections d ON a.section_id = d.id
			LEFT JOIN categories e ON a.category_id = e.id
			LEFT JOIN source_news f ON a.source = f.id
			WHERE a.id = ".$id;
			$resultRow = mysqli_query($con, $sqlRow);
			$post = mysqli_fetch_array($resultRow, MYSQLI_ASSOC);
			
			$id = isset($post['id'])?intval($post['id']):0;
			
			if(!empty($id)){
				$title 						= isset($post['title'])?$post['title']:"";
				$alias 						= isset($post['alias'])?$post['alias']:"";
				$subtitle 					= isset($post['subtitle'])?$post['subtitle']:"";
				$subtitle_alias 			= !empty($subtitle)?str_replace(" ","-",strtolower($subtitle)):"";
				$foto_type 					= isset($post['foto_type'])?$post['foto_type']:"";
				$foto_name 					= isset($post['foto_name'])?$post['foto_name']:"";
				$foto_caption 				= isset($post['foto_caption'])?$post['foto_caption']:"";
				$foto_position 				= "left";
				$foto_source 				= isset($post['foto_source'])?$post['foto_source']:"";
				$introtext 					= isset($post['introtext'])?(string) $post['introtext']:"";
				$fulltexts 					= isset($post['fulltexts'])?$post['fulltexts']:"";
				$section_id 				= isset($post['section_id'])?intval($post['section_id']):0;
				$category_id 				= isset($post['category_id'])?intval($post['category_id']):0;
				$publish 					= isset($post['publish'])?intval($post['publish']):0;
				$frontpage_section 			= isset($post['frontpage_section'])?intval($post['frontpage_section']):0;
				$frontpage_category 		= isset($post['frontpage_category'])?intval($post['frontpage_category']):0;
				$written_by 				= isset($post['written_by'])?intval($post['written_by']):0;
				$editor_by 					= isset($post['editor_by'])?intval($post['editor_by']):0;
				$editor_video_by 			= isset($post['editor_video_by'])?$post['editor_video_by']:"";
				$written_date 				= isset($post['written_date'])?$post['written_date']:"";
				$publish_date 				= isset($post['publish_date'])?$post['publish_date']:"";
				$source 					= isset($post['source'])?intval($post['source']):0;
				$livereport 				= 0;
				$youtube 					= isset($post['youtube'])?$post['youtube']:"";
				$related_id 				= isset($post['related_id'])?$post['related_id']:"";
				$editor 					= isset($post['editor'])?$post['editor']:"";
				$editor_fullname 			= isset($post['editor_fullname'])?$post['editor_fullname']:"";
				$editor_id 					= isset($post['editor_id'])?intval($post['editor_id']):0;
				$hit 						= 0;
				$section 					= isset($post['section'])?$post['section']:"";
				$writter 					= isset($post['writter'])?$post['writter']:"";
				$writter_fullname 			= isset($post['writter_fullname'])?$post['writter_fullname']:"";
				$writter_id 				= isset($post['writter_id'])?intval($post['writter_id']):0;
				$sstatus 					= isset($post['sstatus'])?intval($post['sstatus']):0;
				$c_title 					= isset($post['c_title'])?$post['c_title']:"";
				$c_alias 					= isset($post['c_alias'])?$post['c_alias']:"";
				$s_title 					= isset($post['s_title'])?$post['s_title']:"";
				$name_source 				= isset($post['name_source'])?$post['name_source']:"";
				$url_source 				= isset($post['url_source'])?$post['url_source']:"";
				$quote_by 					= isset($post['quote_by'])?intval($post['quote_by']):0;
				$arrFotoName 				= explode("/",$foto_name);
				$foto_cross_domain 			= isset($arrFotoName[1])?1:0;
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
					$foto_source = str_replace("?"," ",$foto_source);
				}
				if(!mb_check_encoding($fulltexts, 'UTF-8')){
					$fulltexts = mb_convert_encoding ($fulltexts, 'UTF-8');
				}  
				
				$arrInsert = array();
				$arrInsert['id'] = $id;
				$arrInsert['title'] = $title;
				$arrInsert['alias'] = $alias;
				$arrInsert['subtitle'] = $subtitle;
				$arrInsert['subtitle_alias'] = $subtitle_alias;
				$arrInsert['foto_type'] = $foto_type;
				$arrInsert['foto_name'] = $foto_name;
				$arrInsert['foto_cross_domain'] = $foto_cross_domain;
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
				$arrInsert['editor_video_by'] = $editor_video_by;
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
				$arrInsert['writter'] = $writter_id;
				$arrInsert['writter_username'] = $writter;
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
				
				$responseInsertOs = $opensearch->insert($index, $arrInsert);
				
				/* echo "<pre>";
				print_r($responseInsertOs);
				print_r($arrInsert);
				echo "</pre>"; */
				
				if($responseInsertOs['status']){
					$totalSyncOs++; 
				} else {
					echo "<pre>";
					print_r($responseInsertOs);
					print_r($arrInsert);
					echo "</pre>";
				}	
			}	
		}
	}		
	
	
	echo "Total SYNC RDS ke OS : ".$totalSyncOs."<br>";
	
	mysqli_free_result($result);
	mysqli_close($con);
	unset($opensearch);
}	

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>