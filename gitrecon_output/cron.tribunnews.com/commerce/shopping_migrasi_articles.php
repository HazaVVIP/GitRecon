<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

/* 
Running in cmd / command
- sudo -u cron /usr/bin/php7.4 /var/www/html/web-cron/commerce/shopping_migrasi_articles.php
*/

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";
include DOC_ROOT."lib/Writelog.php";

$site = "shopping";

if(!empty($site)){
	$writelog = new Writelog();
	$writelog->Log(PATH_ROOT."/logs/","".$site."-articles");

	$lastid = 0;
	$total = 0;
	$filename = PATH_ROOT . "/data/commerce/".$site."_lastid_articles.txt";
	$valueLog = file_get_contents($filename);
	if ($valueLog !== FALSE) {
		$lastid = $valueLog;
	}

	$index = $site.".articles";
	
	//OS
	$elasticsearch = new Opensearch();
	$elasticsearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

	$opensearch = new Opensearch();
	$opensearch->init(OS_COMMERCE_URL,OS_COMMERCE_USERNAME,OS_COMMERCE_PASSWORD,true);
	
	$opensearchAllNetwork = new Opensearch();
	$opensearchAllNetwork->init(OS_ALLNETWOORK_URL,OS_ALLNETWOORK_USERNAME,OS_ALLNETWOORK_PASSWORD,true);
	
	if (empty($lastid)) {
		$condition = array("match_all"=>new stdClass);
		$fields = array();
		$sort = array("id" => "asc");
		$start = 0;
		$limit = 150;
		$response = $elasticsearch->find($index,$condition,$fields,$sort,$start,$limit);
		
		$response_total = $elasticsearch->count_total($index,$condition);
	} else {
		$condition = array("range"=>array("id"=>array("gt"=>$lastid)));
		$fields = array();
		$sort = array("id" => "asc");
		$start = 0;
		$limit = 150;
		$response = $elasticsearch->find($index,$condition,$fields,$sort,$start,$limit);
		
		$response_total = $elasticsearch->count_total($index,$condition);
	}

	$con = mysqli_connect(RDS_TBO_HOST,RDS_TBO_USERNAME,RDS_TBO_PASSWORD,$site);
	if (mysqli_connect_errno()) {
		echo "Failed to connect to MySQL: " . mysqli_connect_error();
		exit();
	}

	if($response['status']){
		$totalData = 0;
		if($response_total['status']){
			$totalData = isset($response_total['total'])?$response_total['total']:0;
		} 
		$arrPosts = isset($response['data'])?$response['data']:null;
		
		if($totalData > 0){
			foreach($arrPosts as $idx => $post){
				$id 						= isset($post['_source']['id'])?intval($post['_source']['id']):0;
				$title 						= isset($post['_source']['title'])?$post['_source']['title']:"";
				$alias 						= isset($post['_source']['alias'])?$post['_source']['alias']:"";
				$subtitle 					= isset($post['_source']['subtitle'])?$post['_source']['subtitle']:"";
				$subtitle_alias 			= isset($post['_source']['subtitle_alias'])?$post['_source']['subtitle_alias']:"";
				$keyword 					= isset($post['_source']['keyword'])?$post['_source']['keyword']:"";
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
				$id_konten_kreatif 			= isset($post['_source']['id_konten_kreatif'])?intval($post['_source']['id_konten_kreatif']):0;
				$arrFotoName 				= explode("/",$foto_name);
				$foto_cross_domain 			= isset($arrFotoName[1])?1:0;
				$modified_date 				= isset($post['modified_date'])?$post['modified_date']:null;
				$index_year 				= isset($post['_source']['publish_date'])?date("Y",strtotime($post['_source']['publish_date'])):"";
				
				$normalizeChars = array(
					'Š'=>'S', 'š'=>'s', 'Ð'=>'Dj','Ž'=>'Z', 'ž'=>'z', 'À'=>'A', 'Á'=>'A', 'Â'=>'A', 'Ã'=>'A', 'Ä'=>'A',
					'Å'=>'A', 'Æ'=>'A', 'Ç'=>'C', 'È'=>'E', 'É'=>'E', 'Ê'=>'E', 'Ë'=>'E', 'Ì'=>'I', 'Í'=>'I', 'Î'=>'I',
					'Ï'=>'I', 'Ñ'=>'N', 'Ń'=>'N', 'Ò'=>'O', 'Ó'=>'O', 'Ô'=>'O', 'Õ'=>'O', 'Ö'=>'O', 'Ø'=>'O', 'Ù'=>'U', 'Ú'=>'U',
					'Û'=>'U', 'Ü'=>'U', 'Ý'=>'Y', 'Þ'=>'B', 'ß'=>'Ss','à'=>'a', 'á'=>'a', 'â'=>'a', 'ã'=>'a', 'ä'=>'a',
					'å'=>'a', 'æ'=>'a', 'ç'=>'c', 'è'=>'e', 'é'=>'e', 'ê'=>'e', 'ë'=>'e', 'ì'=>'i', 'í'=>'i', 'î'=>'i',
					'ï'=>'i', 'ð'=>'o', 'ñ'=>'n', 'ń'=>'n', 'ò'=>'o', 'ó'=>'o', 'ô'=>'o', 'õ'=>'o', 'ö'=>'o', 'ø'=>'o', 'ù'=>'u',
					'ú'=>'u', 'û'=>'u', 'ü'=>'u', 'ý'=>'y', 'ý'=>'y', 'þ'=>'b', 'ÿ'=>'y', 'ƒ'=>'f',
					'ă'=>'a', 'î'=>'i', 'â'=>'a', 'ș'=>'s', 'ț'=>'t', 'Ă'=>'A', 'Î'=>'I', 'Â'=>'A', 'Ș'=>'S', 'Ț'=>'T',
				);
				$foto_name = strtr($foto_name, $normalizeChars);
				$subtitle = strtr($subtitle, $normalizeChars);
				$subtitle_alias = strtr($subtitle_alias, $normalizeChars);
				$subtitle_alias = str_replace("_","-",$subtitle_alias);
				
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
				
				if(!mb_check_encoding($title, 'UTF-8')){
					$title = mb_convert_encoding ($title, 'UTF-8');
					$title = str_replace("?","",$title);
				}
				/* if(!mb_check_encoding($subtitle, 'UTF-8')){
					$subtitle = mb_convert_encoding ($subtitle, 'UTF-8');
					$subtitle = str_replace("?"," ",$subtitle);
				} */
				if(!mb_check_encoding($introtext, 'UTF-8')){
					$introtext = mb_convert_encoding ($introtext, 'UTF-8');
					$introtext = str_replace("?","",$introtext);
				}
				if(!mb_check_encoding($foto_caption, 'UTF-8')){
					$foto_caption = mb_convert_encoding ($foto_caption, 'UTF-8');
					$foto_caption = str_replace("?","",$foto_caption);
				}
				if(!mb_check_encoding($foto_name, 'UTF-8')){
					$foto_name = mb_convert_encoding ($foto_name, 'UTF-8');
					$foto_name = str_replace("?","",$foto_name);
				}
				if(!mb_check_encoding($foto_source, 'UTF-8')){
					$foto_source = mb_convert_encoding ($foto_source, 'UTF-8');
					$foto_source = str_replace("?"," ",$foto_source);
				}
				if(!mb_check_encoding($fulltexts, 'UTF-8')){
					$fulltexts = mb_convert_encoding ($fulltexts, 'UTF-8');
				} 
				if($modified_date == "0000-00-00 00:00:00"){
					$modified_date = null;
				}
				
				$sqlRow = "SELECT c.id as tagging_id, c.title as tagging_title, c.alias as tagging_alias, a.written_date, a.publish_date
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
					
					$written_date = $post['written_date'];
					$publish_date = $post['publish_date'];
					$index_year = date("Y",strtotime($publish_date));
				}
				
				$sqlArticleAddon = "SELECT kategori, affiliate FROM articles WHERE id = ".$id;
				$resultArticleAddon = mysqli_query($con, $sqlArticleAddon);
				$rowArticleAddon = mysqli_fetch_array($resultArticleAddon, MYSQLI_ASSOC);
				$kategori  = isset($rowArticleAddon['kategori'])?$rowArticleAddon['kategori']:"";
				$affiliate  = isset($rowArticleAddon['affiliate'])?intval($rowArticleAddon['affiliate']):0;
				
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
				$arrInsert['kategori'] = $kategori;
				$arrInsert['affiliate'] = $affiliate;
				$arrInsert['modified_date'] = $modified_date;
				$arrInsert['index_year'] = $index_year;
				if(count($arrTaging) > 0){
					$arrInsert['tagging'] = $arrTaging;
				}
				if(!empty($id_konten_kreatif)){
					$arrInsert['id_konten_kreatif'] = $id_konten_kreatif;
				}	
				
				$allnetwork_id = microtime(true);
				$allnetwork_id = str_replace(".","",$allnetwork_id);
				$allnetwork_id = intval($allnetwork_id);
				$arrInsert['allnetwork_id'] = $allnetwork_id;
				
				$responseInsertOs = $opensearch->insert($index, $arrInsert);
				
				/* echo "<pre>";
				print_r($responseInsertOs);
				print_r($arrInsert);
				echo "</pre>"; */
				
				if($responseInsertOs['status']){
					$total++; 
					
					$whereAllNetwork = array();
			
					array_push($whereAllNetwork,array("match_phrase" => array("domain_id" => $id)));
					array_push($whereAllNetwork,array("match_phrase" => array("domain" => $site)));
					
					$queryAllNetwork = array("bool" =>
									array("must" =>
										$whereAllNetwork
									)
							);
					$fields = array("id");
					$responseCheck = $opensearchAllNetwork->findOne("tribunnetwork-articles",$queryAllNetwork,$fields);
					
					if(!$responseCheck['status']){
						$arrInsertAllNetwork = array();
						$arrInsertAllNetwork = $arrInsert;
						$arrInsertAllNetwork['domain_id'] = $id;
						$arrInsertAllNetwork['domain'] = $site;
						unset($arrInsertAllNetwork['id']);
						unset($arrInsertAllNetwork['frontpage_section']);
						unset($arrInsertAllNetwork['frontpage_category']);
						unset($arrInsertAllNetwork['quote_by']);
						unset($arrInsertAllNetwork['hit']);
						unset($arrInsertAllNetwork['allnetwork_id']);
						$arrInsertAllNetwork['id'] = $allnetwork_id;
						
						$responseInsertOsAllNetwork = $opensearchAllNetwork->insert("tribunnetwork-articles", $arrInsertAllNetwork);

						sleep(1);
					} else {
						$allnetwork_id = isset($responseCheck['data']['_id'])?intval($responseCheck['data']['_id']):0;
						
						if(!empty($allnetwork_id)){
							$dataUpdateOS = array();
							$dataUpdateOS['allnetwork_id'] = $allnetwork_id;

							$responseUpdateOs = $opensearch->updateOne($index,$id,$dataUpdateOS);
						}
					}
				} else {
					echo "<pre>";
					print_r($responseInsertOs);
					print_r($arrInsert);
					echo "</pre>";
				} 	
				
				$lastid = $id;
			}	
		} else {
			/* $lastid = "";
			if (!$handle = fopen($filename, 'w+')) {
				die("Cannot open file $filename");
			}
			if (fwrite($handle, $lastid) === FALSE) {
				die("Cannot write to file $this->log_file");
			} */
		}
		
		echo "TOTAL : " . $totalData . "\n";
		echo "TOTAL MIGRASI : " . $total . "\n";
		echo "LAST ID : " . $lastid . "\n";
		if (!empty($lastid)) {
			if (!$handle = fopen($filename, 'w+')) {
				die("Cannot open file $filename");
			}
			if (fwrite($handle, $lastid) === FALSE) {
				die("Cannot write to file $this->log_file");
			}
			
			$loginfo = "TOTAL = ".$totalData." | TOTAL MIGRASI = ".$total." | LAST ID = ".$lastid."\n";
			$writelog->doLogInfo($loginfo);
		}
	}

	mysqli_close($con);
	$writelog->closeLog();
	unset($opensearch);
	unset($elasticsearch);
}	

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>