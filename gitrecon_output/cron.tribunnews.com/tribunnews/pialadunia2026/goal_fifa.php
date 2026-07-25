<?php
set_time_limit(0); 
ini_set('max_execution_time', 0);
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/simple_html_dom.php";
include DOC_ROOT."lib/Opensearch.php";

$countries = [
        "mexico" => "Meksiko",
        "south africa" => "Afrika Selatan",
        "south korea" => "Korea Selatan",
		"czechia" => "Ceko",
        "canada" => "Kanada",
        "bosnia" => "Bosnia",
        "qatar" => "Qatar",
        "switzerland" => "Swiss",
        "brazil" => "Brasil",
        "morocco" => "Maroko",
        "haiti" => "Haiti",
        "scotland" => "Skotlandia",
        "united states" => "Amerika Serikat",
        "paraguay" => "Paraguay",
        "australia" => "Australia",
        "turkiye" => "Turki",
        "germany" => "Jerman",
        "curacao" => "Curacao",
        "ivory coast" => "Pantai Gading",
        "ecuador" => "Ekuador",
        "netherlands" => "Belanda",
        "japan" => "Jepang",
        "sweden" => "Swedia",
        "tunisia" => "Tunisia",
        "belgium" => "Belgia",
        "egypt" => "Mesir",
        "iran" => "Iran",
        "new zealand" => "Selandia Baru",
        "spain" => "Spanyol",
        "cape verde" => "Tanjung Verde",
        "saudi arabia" => "Arab Saudi",
        "uruguay" => "Uruguay",
        "france" => "Prancis",
        "senegal" => "Senegal",
		"iraq" => "Irak",
        "norway" => "Norwegia",
        "argentina" => "Argentina",
        "algeria" => "Aljazair",
        "austria" => "Austria",
        "jordan" => "Yordania",
        "portugal" => "Portugal",
        "dr congo" => "RD Kongo",
        "uzbekistan" => "Uzbekistan",
        "colombia" => "Kolombia",
        "england" => "Inggris",
        "croatia" => "Kroasia",
        "ghana" => "Ghana",
        "panama" => "Panama"
    ];

$hari = [
    'Sunday' => 'Minggu',
    'Monday' => 'Senin',
    'Tuesday' => 'Selasa',
    'Wednesday' => 'Rabu',
    'Thursday' => 'Kamis',
    'Friday' => 'Jumat',
    'Saturday' => 'Sabtu'
];

$bulan = [
    'January' => 'Januari',
    'February' => 'Februari',
    'March' => 'Maret',
    'April' => 'April',
    'May' => 'Mei',
    'June' => 'Juni',
    'July' => 'Juli',
    'August' => 'Agustus',
    'September' => 'September',
    'October' => 'Oktober',
    'November' => 'November',
    'December' => 'Desember'
];

$countries_short = [
    "mexico" => "MEX",
    "south africa" => "RSA",
    "south korea" => "KOR",
	"czechia" => "CZE",
    "canada" => "CAN",
    "bosnia" => "BIH",
    "qatar" => "QAT",
    "switzerland" => "SUI",
    "brazil" => "BRA",
    "morocco" => "MAR",
    "haiti" => "HAI",
    "scotland" => "SCO",
    "united states" => "USA",
    "paraguay" => "PAR",
    "australia" => "AUS",
	"turkiye" => "TUR",
    "germany" => "GER",
    "curacao" => "CUW",
    "ivory coast" => "CIV",
    "ecuador" => "ECU",
    "netherlands" => "NED",
    "japan" => "JPN",
	"sweden" => "SWE",
    "tunisia" => "TUN",
    "belgium" => "BEL",
    "egypt" => "EGY",
    "iran" => "IRN",
    "new zealand" => "NZL",
    "spain" => "ESP",
    "cape verde" => "CPV",
    "saudi arabia" => "KSA",
    "uruguay" => "URU",
    "france" => "FRA",
    "senegal" => "SEN",
	"iraq" => "IRQ",
    "norway" => "NOR",
    "argentina" => "ARG",
    "algeria" => "ALG",
    "austria" => "AUT",
    "jordan" => "JOR",
    "portugal" => "POR",
	"dr congo" => "COD",
    "uzbekistan" => "UZB",
    "colombia" => "COL",
    "england" => "ENG",
    "croatia" => "CRO",
    "ghana" => "GHA",
    "panama" => "PAN"
];



$opensearchTBO = new Opensearch();
$opensearchTBO->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);

$arrFindCountryInd = array("Bosnia dan Herzegovina","Curaçao","Republik Demokratik Kongo");
$arrReplCountryInd = array("Bosnia","Curacao","RD Kongo");

//// Top Skor & Assist
$liga = "piala-dunia-2026";
$url_topskor = "https://www.transfermarkt.co.id/weltmeisterschaft/scorerliste/pokalwettbewerb/FIWC/ajax/yw1/sort/goals.desc";
$url_assist = "https://www.transfermarkt.co.id/weltmeisterschaft/scorerliste/pokalwettbewerb/FIWC/ajax/yw1/sort/assists.desc";

$cookie = COOKIE_TRANSFERMARKT;	
$proxys = [
			'tcp://kmpoqebm:0gzxkwmw72fj@142.111.67.146:5611',
			'tcp://kmpoqebm:0gzxkwmw72fj@191.96.254.138:6185',
			'tcp://kmpoqebm:0gzxkwmw72fj@104.239.107.47:5699',
			'tcp://kmpoqebm:0gzxkwmw72fj@198.105.121.200:6462',
			'tcp://kmpoqebm:0gzxkwmw72fj@38.154.203.95:5863',
			'tcp://kmpoqebm:0gzxkwmw72fj@209.127.138.10:5784',
		  ];

$user_agents = [
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
	];
$random_user_agent = $user_agents[array_rand($user_agents)];
$random_proxy = $proxys[array_rand($proxys)];

$options = array(
  'http'=>array(
	'method'=>"GET",
	'header'=>"Accept-language: en-US,en;q=0.9,id-ID;q=0.8,id;q=0.7,pl;q=0.6\r\n" .
		  "Cookie: ".$cookie."\r\n" .
		  "Referer: ".$url_topskor."\r\n" .
		  "User-Agent: ".$random_user_agent."\r\n",
	//"proxy" => $random_proxy,
	"request_fulluri" => true,
	"timeout" => 3
  )
);

$context = stream_context_create($options);
$results = @file_get_contents($url_topskor, false, $context);

$http_code = "";
$status_response_header = isset($http_response_header[0])?$http_response_header[0]:"";
if(!empty($status_response_header)){
	preg_match('{HTTP\/\S*\s(\d{3})}', $status_response_header, $match);
	$http_code = isset($match[1])?$match[1]:"";
}

echo $url_topskor." : ".$http_code." (". $_SERVER['REMOTE_ADDR'].")<br><br>";
/* echo "<pre>";
print_r($results);
echo "</pre>"; */

if($results != false){
	$dom = new DOMDocument('1.0', 'UTF-8');
	$dom->preserveWhiteSpace = false; 
	@$dom->loadHTML($results);
	
	$xpath = new DOMXPath($dom);
	
	$rows = $xpath->query("//table[contains(@class,'items')]/tbody/tr");
	$rankGoal = 1;
	
	foreach ($rows as $row) {
		$urutanNode = $xpath->query(".//td[contains(@class,'zentriert')][1]", $row);
		$urutan = $urutanNode->length ? trim($urutanNode->item(0)->textContent) : '';
	
		$nameNode = $xpath->query(".//td[contains(@class,'hauptlink')]/a", $row);
		$name = $nameNode->length ? trim($nameNode->item(0)->textContent) : '';

		$negara = '';
		$clubImg = $xpath->query(".//td[a[contains(@href,'/verein/')]]//img", $row);
		if($clubImg->length){
			$negara = trim($clubImg->item(0)->getAttribute("alt"));
		}

		if(empty($negara)){
			$clubText = $xpath->query(".//td[a[contains(@href,'/verein/')]]/a", $row);
			if($clubText->length){
				$negara = trim($clubText->item(0)->textContent);
			}
		}

		$goalNode = $xpath->query(".//td[contains(@class,'zentriert')][6]", $row);
		$goals = $goalNode->length ? intval(trim($goalNode->item(0)->textContent)) : 0;

		/* echo "Nama  : $name <br>";
		echo "Negara  : $negara <br>";
		echo "Gol   : $goals <br>";
		echo "<hr>";  */

		if(!empty($name) && !empty($negara) && !empty($goals)){
			$countriesIdToEn = array_change_key_case(array_flip($countries), CASE_LOWER);
			$negara = str_replace($arrFindCountryInd,$arrReplCountryInd,$negara);
			$key = strtolower(trim($negara));
			$negara_eng = ucfirst($countriesIdToEn[$key]) ?? $negara;
			
			$where2 = array();
			array_push($where2,array("match_phrase" => array("negara_eng" => $negara_eng)));
			array_push($where2,array("match_phrase" => array("index_year" => "2026")));
			
			$query2 = array();
			if(count($where2) > 0){
				$query2 = array("bool" =>
								array("filter" =>
									$where2
								)
							);
			}
			$fields2 = array("id","image_negara_link");
			$response2 = $opensearchTBO->findOne("klasemen_pialadunia",$query2,$fields2);

			$image_klub_link2 = "";
			if($response2['status']){
				$image_klub_link2 = isset($response2['data']['_source']['image_negara_link'])?$response2['data']['_source']['image_negara_link']:"";
				$image_klub_link2 = str_replace(array("https://t-1.tstatic.net","https://asset-1.tstatic.net"),"https://asset-1.tribunnews.com",$image_klub_link2);
			}	

			$where1 = array();
			array_push($where1,array("match_phrase" => array("player_name" => $name)));
			array_push($where1,array("match_phrase" => array("klub" => $negara_eng)));
			array_push($where1,array("match_phrase" => array("liga" => $liga)));
			array_push($where1,array("match_phrase" => array("jenis" => "goal")));
			
			$query1 = array("bool" =>
							array("must" =>
								$where1
							)
					);
			$fields1 = array("id");
			$response1 = $opensearchTBO->findOne("topskorassist",$query1,$fields1);

			if($response1['status']){
				$id = isset($response1['data']['_source']['id'])?intval($response1['data']['_source']['id']):0;
				
				$arrUpdateGoal = array();
				$arrUpdateGoal['urutan'] = intval($urutan);
				$arrUpdateGoal['val'] = intval($goals);
				
				$responseUpdateGoal = $opensearchTBO->updateOne("topskorassist", $id, $arrUpdateGoal);
				
				echo "Update";
				echo "<pre>";
				print_r($arrUpdateGoal);
				print_r($responseUpdateGoal);
				echo "</pre>"; 
				
				if($responseUpdateGoal['status']){
					
				}
			} else {
				$arrInsertGoal = array();
				$arrInsertGoal['id'] = time()+$rankGoal;
				$arrInsertGoal['klub'] = $negara_eng;
				$arrInsertGoal['negara'] = $negara;
				$arrInsertGoal['negara_eng'] = $negara_eng;
				$arrInsertGoal['urutan'] = intval($urutan);
				$arrInsertGoal['player_name'] = $name;
				$arrInsertGoal['image_klub_link'] = $image_klub_link2;
				$arrInsertGoal['liga'] = $liga;
				$arrInsertGoal['val'] = intval($goals);
				$arrInsertGoal['jenis'] = 'goal';
				
				$responseInsertGoal = $opensearchTBO->insert("topskorassist", $arrInsertGoal);
				
				echo "Insert";
				echo "<pre>";
				print_r($arrInsertGoal);
				print_r($responseInsertGoal);
				echo "</pre>";
				
				if($responseInsertGoal['status']){
					
				}
				
				$rankGoal++;
			}	
		}
	}
}	


if(!empty($url_assist)){
	$results1 = @file_get_contents($url_assist, false, $context);
	$rankAssist = 1;
	
	$http_code = "";
	$status_response_header = isset($http_response_header[0])?$http_response_header[0]:"";
	if(!empty($status_response_header)){
		preg_match('{HTTP\/\S*\s(\d{3})}', $status_response_header, $match);
		$http_code = isset($match[1])?$match[1]:"";
	}
	
	echo $url_assist." : ".$http_code." (". $_SERVER['REMOTE_ADDR'].")<br><br>";
	/* echo "<pre>";
	print_r($results1);
	echo "</pre>"; */

	if($results1 != false){
		$dom1 = new DOMDocument('1.0', 'UTF-8');
		$dom1->preserveWhiteSpace = false; 
		@$dom1->loadHTML($results1);
		
		$xpath1 = new DOMXPath($dom1);
		
		$rows = $xpath1->query("//table[contains(@class,'items')]/tbody/tr");
		
		foreach ($rows as $row) {
			$urutanNode = $xpath1->query(".//td[contains(@class,'zentriert')][1]", $row);
			$urutan = $urutanNode->length ? trim($urutanNode->item(0)->textContent) : '';
		
			$nameNode = $xpath1->query(".//td[contains(@class,'hauptlink')]/a", $row);
			$name = $nameNode->length ? trim($nameNode->item(0)->textContent) : '';

			$negara = '';
			$clubImg = $xpath1->query(".//td[a[contains(@href,'/verein/')]]//img", $row);
			if($clubImg->length){
				$negara = trim($clubImg->item(0)->getAttribute("alt"));
			}

			if(empty($negara)){
				$clubText = $xpath1->query(".//td[a[contains(@href,'/verein/')]]/a", $row);
				if($clubText->length){
					$negara = trim($clubText->item(0)->textContent);
				}
			}

			$assistsNode = $xpath1->query(".//td[contains(@class,'zentriert')][7]", $row);
			$assists = $assistsNode->length ? intval(trim($assistsNode->item(0)->textContent)) : 0;
			
			/* echo "Nama  	: $name <br>";
			echo "Negara  : $negara <br>";
			echo "Assist   	: $assists <br>";
			echo "<hr>"; */
			
			if(!empty($name) && !empty($negara) && !empty($assists)){
				$countriesIdToEn = array_change_key_case(array_flip($countries), CASE_LOWER);
				$negara = str_replace($arrFindCountryInd,$arrReplCountryInd,$negara);
				$key = strtolower(trim($negara));
				$negara_eng = ucfirst($countriesIdToEn[$key]) ?? $negara;
				
				$where3 = array();
				array_push($where3,array("match_phrase" => array("negara_eng" => $negara_eng)));
				array_push($where3,array("match_phrase" => array("index_year" => "2026")));
				
				$query3 = array();
				if(count($where3) > 0){
					$query3 = array("bool" =>
									array("filter" =>
										$where3
									)
								);
				}
				$fields3 = array("id","image_negara_link");
				$response3 = $opensearchTBO->findOne("klasemen_pialadunia",$query3,$fields3);
				
				$image_klub_link3 = "";
				if($response3['status']){
					$image_klub_link3 = isset($response3['data']['_source']['image_negara_link'])?$response3['data']['_source']['image_negara_link']:"";
					$image_klub_link3 = str_replace(array("https://t-1.tstatic.net","https://asset-1.tstatic.net"),"https://asset-1.tribunnews.com",$image_klub_link3);
				}	
				
				$where4 = array();
				array_push($where4,array("match_phrase" => array("player_name" => $name)));
				array_push($where4,array("match_phrase" => array("klub" => $negara_eng)));
				array_push($where4,array("match_phrase" => array("liga" => $liga)));
				array_push($where4,array("match_phrase" => array("jenis" => "assist")));
				
				$query4 = array("bool" =>
								array("must" =>
									$where4
								)
						);
				$fields4 = array("id");
				$response4 = $opensearchTBO->findOne("topskorassist",$query4,$fields4);

				if($response4['status']){
					$id = isset($response4['data']['_source']['id'])?intval($response4['data']['_source']['id']):0;
					
					$arrUpdateAssist = array();
					$arrUpdateAssist['urutan'] = intval($urutan);
					$arrUpdateAssist['val'] = intval($assists);
					
					$responseUpdateAssist = $opensearchTBO->updateOne("topskorassist", $id, $arrUpdateAssist);
					
					echo "Update";
					echo "<pre>";
					print_r($arrUpdateAssist);
					print_r($responseUpdateAssist);
					echo "</pre>";
					
					if($responseUpdateAssist['status']){
						
					}
				} else {
					$arrInsertAssist = array();
					$arrInsertAssist['id'] = time()+$rankAssist;
					$arrInsertAssist['klub'] = $negara_eng;
					$arrInsertAssist['negara'] = $negara;
					$arrInsertAssist['negara_eng'] = $negara_eng;
					$arrInsertAssist['urutan'] = intval($urutan);
					$arrInsertAssist['player_name'] = $name;
					$arrInsertAssist['image_klub_link'] = $image_klub_link3;
					$arrInsertAssist['liga'] = $liga;
					$arrInsertAssist['val'] = intval($assists);
					$arrInsertAssist['jenis'] = 'assist';
					
					$responseInsertAssist = $opensearchTBO->insert("topskorassist", $arrInsertAssist);
					
					echo "Insert";
					echo "<pre>";
					print_r($arrInsertAssist);
					print_r($responseInsertAssist);
					echo "</pre>"; 
					
					if($responseInsertAssist['status']){
						
					}
					
					$rankAssist++;
				}
			}
		}
	}	
}
//// End Top Skor & Assist

unset($opensearchTBO);

echo 'Total execution time in seconds: ' . (microtime(true) - $time_start);


$opts = array(
    'http' => array(
        'method' => "GET",
        'header' => "Accept-language: en\r\n" .
                    "User-Agent: Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Tribunbot/1.0; +http://tribunnews.com/bot.html) Chrome/W.X.Y.Z Safari/537.36\r\n",
        'timeout' => 5
    ),
    'ssl' => array (
        'verify_peer'      => false,
        'verify_peer_name' => false,
    )
);
$context = stream_context_create($opts);

file_get_contents('https://wilis.tribunnews.com/tcache/update_custom_many_memcache/klasemen_piala-dunia-2026', false, $context);
file_get_contents('https://superskor.tribunnews.com/tcache/upd_jadwal_klasemen', false, $context);
file_get_contents('https://api.tribunnews.com/tcache/update_custom_memcache_redis/klasemen_piala-dunia-2026', false, $context);
?>