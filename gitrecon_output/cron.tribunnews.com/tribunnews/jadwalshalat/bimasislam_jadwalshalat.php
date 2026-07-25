<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
ini_set("memory_limit", "-1");
set_time_limit(0);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$bln = isset($_GET["bln"])?intval($_GET["bln"]):date("n");
$thn = isset($_GET["thn"])?intval($_GET["thn"]):date("Y");

	
$cookie_bimasislam = 'cookiesession1=678B29AD42E14DFAC60EDE3007D6091F; _ga=GA1.1.1051080580.1766395158; _ga_SZ803KP95M=GS2.1.s1766395341$o1$g1$t1766395402$j60$l0$h0; _ga_WBZQPS14S6=GS2.1.s1773818875$o16$g0$t1773818875$j60$l0$h0; PHPSESSID=kmi286tm9960rga04qmoh0fjj0; bimasislam_session=a%3A5%3A%7Bs%3A10%3A%22session_id%22%3Bs%3A32%3A%22c8971762b144c04c6daa5ad6dc5ac289%22%3Bs%3A10%3A%22ip_address%22%3Bs%3A12%3A%2210.11.11.123%22%3Bs%3A10%3A%22user_agent%22%3Bs%3A111%3A%22Mozilla%2F5.0+%28Windows+NT+10.0%3B+Win64%3B+x64%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F147.0.0.0+Safari%2F537.36%22%3Bs%3A13%3A%22last_activity%22%3Bi%3A1778041079%3Bs%3A9%3A%22user_data%22%3Bs%3A0%3A%22%22%3B%7D5cecf5dd63de7884dbd420b720fc821b; _ga_W825VCQ3Z3=GS2.1.s1778041078$o43$g0$t1778041078$j60$l0$h0';

$urlJson = "https://asset-2.tribunnews.com/tribunnews/jadwalshalat/kotakab.json";

$user_agents = [
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
	];
$random_user_agent = $user_agents[array_rand($user_agents)];

$options = array(
  'http'=>array(
	'method'=>"GET",
	'header'=>"Accept-language: en\r\n" .
			  "User-Agent: ".$random_user_agent."\r\n",
			  "timeout" => 1
  )
);

$context = stream_context_create($options);
$results = @file_get_contents($urlJson, false, $context);

$arrInsertJadwalShalat = array();
$arrUpdateJadwalShalat = array();
$id = time();
$no = 1;
$totalinsert = 0;
$totalupdate = 0;

if($results != false){
	$arrKotaKab = json_decode($results, TRUE);
		
	if(count($arrKotaKab) > 0){
		//OS
		$opensearch = new Opensearch();
		$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);
		
		$url_getjadwalshalat = "https://bimasislam.kemenag.go.id/ajax/getShalatbln"; 
		
		foreach($arrKotaKab as $kotakab){
			$id_propinsi = $kotakab['id_propinsi'];
			$val_propinsi = $kotakab['val_propinsi'];
			$id_kotakab = $kotakab['id_kotakab'];
			$val_kotakab = $kotakab['val_kotakab'];
			
			$province_name = $val_propinsi;
			$city_name = $val_kotakab;
			$province_alias = url_alias(strtolower($province_name));
			$city_alias = url_alias(strtolower($city_name));
			
			$postdata = ['x' => $id_propinsi, 'y' => $id_kotakab, 'bln' => $bln, 'thn' => $thn];

			$options = array(
			  'http'=>array(
				'method'=>"POST",
				'header'=>"Accept-language: en\r\n" .
						  "Accept: text/html,application/xhtml+xml\r\n" .
						  "Referer: https://bimasislam.kemenag.go.id/jadwalshalat\r\n" .
						  "Cookie: ".$cookie_bimasislam."\r\n" .
						  "User-Agent: ".$random_user_agent."\r\n",
				'content' => http_build_query($postdata),
				"timeout" => 2
			  )
			);

			$context = stream_context_create($options);
			$results1 = @file_get_contents($url_getjadwalshalat, false, $context);
			
			$http_code = "";
			$status_response_header = isset($http_response_header[0])?$http_response_header[0]:"";
			if(!empty($status_response_header)){
				preg_match('{HTTP\/\S*\s(\d{3})}', $status_response_header, $match);
				$http_code = isset($match[1])?$match[1]:"";
			}
			
			if($results != false){
				echo $url_getjadwalshalat." : ".$http_code." = ".$bln." - ".$thn." - ".$val_propinsi." - ".$val_kotakab."<br><br>";
				
				$arrResultJadwalShalat = json_decode($results1, TRUE);
				
				$arrJadwalShalat = isset($arrResultJadwalShalat['data'])?$arrResultJadwalShalat['data']:array();
				
				if(count($arrJadwalShalat) > 0){
					foreach($arrJadwalShalat as $tglshalat => $jadwalshalat){
						$tanggal = $jadwalshalat['tanggal'];
						$imsak = $jadwalshalat['imsak'];
						$subuh = $jadwalshalat['subuh'];
						$terbit = $jadwalshalat['terbit'];
						$duha = $jadwalshalat['dhuha'];
						$zuhur = $jadwalshalat['dzuhur'];
						$asar = $jadwalshalat['ashar'];
						$magrib = $jadwalshalat['maghrib'];
						$isya = $jadwalshalat['isya'];
						$create_date = date("Y-m-d H:i:s");
						
						$dateClean = preg_replace('/^[^,]+,\s*/', '', $tanggal);
						$dateTime = DateTime::createFromFormat('d/m/Y H:i:s', $dateClean . ' 00:00:00');
						$dt = $dateTime->format('Y-m-d H:i:s');
						$id_dt = $dateTime->format('Y_m_d');

						//echo $tanggal." - ".$tglshalat." - ".$imsak." - ".$subuh." - ".$terbit." - ".$duha." - ".$zuhur." - ".$asar." - ".$maghrib." - ".$isya."<br>";
						
						/* $where = array();

						array_push($where,array("match_phrase" => array("province_name" => $province_name)));
						array_push($where,array("match_phrase" => array("city_name" => $city_name)));
						array_push($where,array("match_phrase" => array("bln" => $bln)));
						array_push($where,array("match_phrase" => array("thn" => $thn)));
						
						$condition = array();
						if(count($where) > 0){
							$condition = array("bool" =>
													array("must" =>
														$where
													)
											  );
						}
						
						$fields = array("id");
						$response = $opensearch->findOne("jadwal_shalat",$condition,$fields);
						
						$stat = "";
						if($response['status']){
							$id = isset($response['data']['_source']['id'])?$response['data']['_source']['id']:0;
							
							$arrUpdate = array();
							$arrUpdate['imsak'] = $imsak;
							$arrUpdate['subuh'] = $subuh;
							$arrUpdate['terbit'] = $terbit;
							$arrUpdate['duha'] = $duha;
							$arrUpdate['zuhur'] = $zuhur;
							$arrUpdate['asar'] = $asar;
							$arrUpdate['magrib'] = $magrib;
							$arrUpdate['isya'] = $isya;
							
							$arrUpdateJadwalShalat[] = [
								'id'  => $id,
								'doc' => $arrUpdate
							];
							
							$totalupdate++;
						} else {  */
							//$id = $id + $no;
							$id = $province_alias."_".$city_alias."_".$city_alias."_".$id_dt;
							$id = md5($id);
							
							$arrInsert = array();
							$arrInsert['id'] = $id;
							$arrInsert['city_name'] = $city_name;
							$arrInsert['city_alias'] = $city_alias;
							$arrInsert['province_name'] = $province_name;
							$arrInsert['province_alias'] = $province_alias;
							$arrInsert['imsak'] = $imsak;
							$arrInsert['subuh'] = $subuh;
							$arrInsert['terbit'] = $terbit;
							$arrInsert['duha'] = $duha;
							$arrInsert['zuhur'] = $zuhur;
							$arrInsert['asar'] = $asar;
							$arrInsert['magrib'] = $magrib;
							$arrInsert['isya'] = $isya;
							$arrInsert['waktu'] = $tanggal;
							$arrInsert['dt'] = $dt;
							$arrInsert['bln'] = intval($bln);
							$arrInsert['thn'] = intval($thn); 
							$arrInsert['create_date'] = $create_date;
							
							$arrInsertJadwalShalat[] = $arrInsert;
						//}
						
						$no++;
					}
				}
			}
		}
		
		if(count($arrInsertJadwalShalat) > 0){
			$responseInsert = $opensearch->bulkInsert('jadwal_shalat', $arrInsertJadwalShalat, 200, 'index');
			
			/* echo "<pre>";
			print_r($arrInsertJadwalShalat);
			print_r($responseInsert);
			echo "</pre>"; */
			
			if ($responseInsert['status']) {
				$totalinsert = $responseInsert['total'];
			} else {
				echo "ERROR: " . $responseInsert['error_reason'] . "\n\n";

				if (!empty($responseInsert['items'])) {
					print_r($responseInsert['items']);
				}
			}
		}
		
		if(count($arrUpdateJadwalShalat) > 0){
			$responseUpdate = $opensearch->bulkUpdate('jadwal_shalat', $arrUpdateJadwalShalat, 200, false);
			
			/* echo "<pre>";
			print_r($arrUpdateJadwalShalat);
			print_r($responseUpdate);
			echo "</pre>"; */
			
			if ($responseUpdate['status']) {
				$totalupdate = $responseUpdate['total'];
			} else {
				echo "ERROR: " . $responseUpdate['error_reason'] . "\n\n";

				if (!empty($responseUpdate['items'])) {
					print_r($responseUpdate['items']);
				}
			}
		}
		
		unset($opensearch);
	}
}	

echo "Total Insert : ".$totalinsert."<br>";
echo "Total Update : ".$totalupdate."<br>";
echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";


function url_alias($str) {
	 $title = strtolower(trim($str));
	 $replacements = ['@'=> "at", '#' => "hash", '$' => "dollar", '%' => "percentage", '&' => "and", '.' => "-", 
				'+' => "plus", '-' => "minus", '*' => "multiply", '/' => "devide", '=' => "equal to",
				'<' => "less than", '<=' => "less than or equal to", '>' => "greater than", '<=' => "greater than or equal to",
		];

	 $title = strtr($title, $replacements);
	 return $urlKey = preg_replace('#[^0-9a-z]+#i', '-', $title);
}
?>