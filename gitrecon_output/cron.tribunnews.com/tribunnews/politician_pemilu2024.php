<?php
ini_set('max_execution_time', '0');
set_time_limit(0);
ini_set('display_errors', 1);
error_reporting(E_ALL);
//error_reporting(0);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

/* 
Running in cmd / command
- sudo -u www-data /usr/bin/php7.4 /var/www/html/web-cron/tribunnews/politician_pemilu2024.php ganjar-pranowo
*/

include DOC_ROOT."config/config.php";
include DOC_ROOT."config/other_config.php";
include DOC_ROOT."lib/Opensearch.php";

$arrProfil = array("ganjar-pranowo", "prabowo-subianto", "anies-baswedan", "muhaimin-iskandar", "mahfud-md", "gibran-rakabuming");

$profil = isset($_SERVER["argv"][1])?$_SERVER["argv"][1]:"";
if(isset($_GET['profil'])){
	$profil = $_GET['profil'];
}	

$totalall = 0;

if(!empty($profil) && in_array($profil, $arrProfil)){
	$api_url = "http://13.228.145.208:8990/api/v1/get_persidential_candidate_articles";

	$ch = curl_init();
	curl_setopt($ch,CURLOPT_URL, $api_url);
	curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,3);
	curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
	$response = curl_exec($ch);
	$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
	curl_close($ch);
	
	if($http_code == 200){
		$arrResponse = json_decode($response, TRUE);
		
		if($arrResponse['code'] == "200"){
			$rows = isset($arrResponse['data'])?$arrResponse['data']:array();
			
			$opensearchTest = new Opensearch();
			$opensearchTest->init(OS_DEV_URL,OS_DEV_USERNAME,OS_DEV_PASSWORD,true);
			
			$opensearchCommerce = new Opensearch();
			$opensearchCommerce->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

			if(count($rows) > 0){
				echo $profil."<br>";
				
				$dataAllDomain = isset($rows[$profil]['article_list'])?$rows[$profil]['article_list']:array();
				
				if(count($dataAllDomain)){
					//Delete
					/* $condition = array("match_phrase" => array("profil" => $profil));
					$response2 = $opensearchCommerce->deleteMany("pilpres2024",$condition); */
					//$response2 = $opensearchTest->deleteMany("pilpres2024",$condition);
					
					foreach($dataAllDomain as $keyDomain => $dataLead){
						//echo "Domain : ".$keyDomain."<br>";

						if(count($dataLead)){
							foreach($dataLead as $valAnies){
								$unique_id = $valAnies['unique_id'];
								$title = $valAnies['title'];
								$introtext = $valAnies['introtext'];
								$publish_date = $valAnies['publish_date'];
								$domain = $valAnies['domain'];
								$article_url = $valAnies['article_url'];
								$photo_url = $valAnies['photo_url'];
								
								$arrUnique = explode("-",$unique_id);
								$id = isset($arrUnique[1])?intval($arrUnique[1]):0;
								
								$unique_id = str_replace("aceh2","aceh",$unique_id);
								$unique_id = str_replace("jambi2","jambi",$unique_id);
								
								$keyDomain = str_replace("aceh2","aceh",$keyDomain);
								$keyDomain = str_replace("jambi2","jambi",$keyDomain);
		
								
								if(!empty($id)){
									$arrInsert = array();
									$arrInsert['id'] = $unique_id;
									$arrInsert['domain_id'] = $id;
									$arrInsert['profil'] = $profil;
									$arrInsert['title'] = $title;
									$arrInsert['introtext'] = $introtext;
									$arrInsert['domain'] = $keyDomain;
									$arrInsert['article_url'] = $article_url;
									$arrInsert['photo_url'] = $photo_url;
									$arrInsert['publish_date'] = $publish_date;
									
									$responseInsert = $opensearchCommerce->insert("pilpres2024", $arrInsert);
									//$responseInsert = $opensearchTest->insert("pilpres2024", $arrInsert);
									
									/* echo "<pre>";
									print_r($responseInsert);
									print_r($arrInsert);
									echo "</pre>"; */
								
									if($responseInsert['status']){
										$totalall++;
									} 
								}
							}
						}
					}
				}
			}
			
			unset($opensearchTest);
			unset($opensearchCommerce);
		}
	}
}

echo "Total : ".$totalall."<br>";

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>
