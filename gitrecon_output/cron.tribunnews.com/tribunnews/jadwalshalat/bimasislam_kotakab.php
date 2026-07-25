<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
ini_set("memory_limit", "-1");
set_time_limit(0);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";


$cookie_bimasislam = 'cookiesession1=678B29AD42E14DFAC60EDE3007D6091F; _ga=GA1.1.1051080580.1766395158; _ga_SZ803KP95M=GS2.1.s1766395341$o1$g1$t1766395402$j60$l0$h0; _ga_WBZQPS14S6=GS2.1.s1773818875$o16$g0$t1773818875$j60$l0$h0; PHPSESSID=kmi286tm9960rga04qmoh0fjj0; bimasislam_session=a%3A5%3A%7Bs%3A10%3A%22session_id%22%3Bs%3A32%3A%22c8971762b144c04c6daa5ad6dc5ac289%22%3Bs%3A10%3A%22ip_address%22%3Bs%3A12%3A%2210.11.11.123%22%3Bs%3A10%3A%22user_agent%22%3Bs%3A111%3A%22Mozilla%2F5.0+%28Windows+NT+10.0%3B+Win64%3B+x64%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F147.0.0.0+Safari%2F537.36%22%3Bs%3A13%3A%22last_activity%22%3Bi%3A1778041079%3Bs%3A9%3A%22user_data%22%3Bs%3A0%3A%22%22%3B%7D5cecf5dd63de7884dbd420b720fc821b; _ga_W825VCQ3Z3=GS2.1.s1778041078$o43$g0$t1778041078$j60$l0$h0';

preg_match('/bimasislam_session=([^;]+)/', $cookie_bimasislam, $matches);
$session_value = $matches[1];

$decoded = urldecode($session_value);

$data_bimasislam = substr($decoded, 0, -32);
$hash_bimasislam = substr($decoded, -32);

$result_bimasislam = unserialize($data_bimasislam);

/* echo $hash_bimasislam;
echo "<pre>";
print_r($result_bimasislam);
echo "</pre>";
echo "<hr>"; */

/////

$arrPropinsi = [
    'c4ca4238a0b923820dcc509a6f75849b' => 'ACEH',
    'c81e728d9d4c2f636f067f89cc14862c' => 'SUMATERA UTARA',
    'eccbc87e4b5ce2fe28308fd9f2a7baf3' => 'SUMATERA BARAT',
    'a87ff679a2f3e71d9181a67b7542122c' => 'RIAU',
    'e4da3b7fbbce2345d7772b0674a318d5' => 'KEPULAUAN RIAU',
    '1679091c5a880faf6fb5e6087eb1b2dc' => 'JAMBI',
    '8f14e45fceea167a5a36dedd4bea2543' => 'BENGKULU',
    'c9f0f895fb98ab9159f51fd0297e236d' => 'SUMATERA SELATAN',
    '45c48cce2e2d7fbdea1afc51c7c6ad26' => 'KEPULAUAN BANGKA BELITUNG',
    'd3d9446802a44259755d38e6d163e820' => 'LAMPUNG',
    '6512bd43d9caa6e02c990b0a82652dca' => 'BANTEN',
    'c20ad4d76fe97759aa27a0c99bff6710' => 'JAWA BARAT',
    'c51ce410c124a10e0db5e4b97fc2af39' => 'DKI JAKARTA',
    'aab3238922bcc25a6f606eb525ffdc56' => 'JAWA TENGAH',
    '9bf31c7ff062936a96d3c8bd1f8f2ff3' => 'D.I. YOGYAKARTA',
    'c74d97b01eae257e44aa9d5bade97baf' => 'JAWA TIMUR',
    '70efdf2ec9b086079795c442636b55fb' => 'BALI',
    '6f4922f45568161a8cdf4ad2299f6d23' => 'NUSA TENGGARA BARAT',
    '1f0e3dad99908345f7439f8ffabdffc4' => 'NUSA TENGGARA TIMUR',
    '98f13708210194c475687be6106a3b84' => 'KALIMANTAN BARAT',
    '3c59dc048e8850243be8079a5c74d079' => 'KALIMANTAN SELATAN',
    'b6d767d2f8ed5d21a44b0e5886680cb9' => 'KALIMANTAN TENGAH',
    '37693cfc748049e45d87b8c7d8b9aacd' => 'KALIMANTAN TIMUR',
    '1ff1de774005f8da13f42943881c655f' => 'KALIMANTAN UTARA',
    '8e296a067a37563370ded05f5a3bf3ec' => 'GORONTALO',
    '4e732ced3463d06de0ca9a15b6153677' => 'SULAWESI SELATAN',
    '02e74f10e0327ad868d138f2b4fdd6f0' => 'SULAWESI TENGGARA',
    '33e75ff09dd601bbe69f351039152189' => 'SULAWESI TENGAH',
    '6ea9ab1baa0efb9e19094440c317e21b' => 'SULAWESI UTARA',
    '34173cb38f07f89ddbebc2ac9128303f' => 'SULAWESI BARAT',
    'c16a5320fa475530d9583c34fd356ef5' => 'MALUKU',
    '6364d3f0f495b6ab9dcf8d3b5c6e0b01' => 'MALUKU UTARA',
    '182be0c5cdcd5072bb1864cdee4d3d6e' => 'PAPUA',
    'e369853df766fa44e1ed0ff613f563bd' => 'PAPUA BARAT',
];

$user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    ];
$random_user_agent = $user_agents[array_rand($user_agents)];

$url_getkotakab = "https://bimasislam.kemenag.go.id/ajax/getKabkoshalat"; 

$arrLocationJadwalShalat = array();
foreach($arrPropinsi as $proid => $proval){
	$postdata = ['x' => $proid];

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
	
	$results = @file_get_contents($url_getkotakab, false, $context);
	$http_code = "";
	if(!empty($status_response_header)){
		preg_match('{HTTP\/\S*\s(\d{3})}', $status_response_header, $match);
		$http_code = isset($match[1])?$match[1]:"";
	}

	//echo $url_getkotakab." : ".$http_code."<br>";

	if($results != false){
		$dom = new DOMDocument();
		libxml_use_internal_errors(true); // biar nggak warning
		$dom->loadHTML('<select>'.$results.'</select>');
		libxml_clear_errors();

		$options = $dom->getElementsByTagName('option');

		$arrKotaKab = [];

		foreach ($options as $opt) {
			$kotakabid = $opt->getAttribute('value');
			$kotakabval  = ucwords(strtolower(trim($opt->nodeValue)));

			$arrLocationJadwalShalat[] = [
				'id_propinsi' => $proid,
				'val_propinsi'  => $proval,
				'id_kotakab' => $kotakabid,
				'val_kotakab'  => $kotakabval
			];
		}
	}
}	

/* if(count($arrLocationJadwalShalat) > 0){
	echo "<pre>";
	print_r($arrLocationJadwalShalat);
	echo "</pre>";
}
 */
header('Content-Type: application/json; charset=utf-8');
echo json_encode($arrLocationJadwalShalat);
/////

//OS
$opensearch = new Opensearch();
//$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);
$opensearch->init(OS_DEV_URL,OS_DEV_USERNAME,OS_DEV_PASSWORD,true);

unset($opensearch);

//echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>