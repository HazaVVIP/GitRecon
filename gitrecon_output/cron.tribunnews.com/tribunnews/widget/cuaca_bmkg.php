<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

/* 
Running in command
- sudo -u www-data /usr/bin/php7.4 /var/www/html/web-cron/tribunnews/widget/cuaca_bmkg.php jakarta
*/

$daerah = isset($_SERVER["argv"][1])?$_SERVER["argv"][1]:"";
if(isset($_GET['daerah'])){
	$daerah = $_GET['daerah'];
}	

$kode_wilayah_tingkat_iv = "31.71.01.1001"; //gambiar, jakarta pusat
if($daerah == "bali"){
	$kode_wilayah_tingkat_iv = "51.71.02.1010"; //dangin putri, denpasar timur
} else if($daerah == "medan"){
	$kode_wilayah_tingkat_iv = "12.71.01.1002"; //medan kota, pusat pasar
} else if($daerah == "bogor"){
	$kode_wilayah_tingkat_iv = "32.01.24.2012"; //ciawi, ciawi
} else  if($daerah == "bandung"){
	$kode_wilayah_tingkat_iv = "32.73.13.1003"; //burangrang, lengkong
} else if($daerah == "bekasi"){
	$kode_wilayah_tingkat_iv = "32.75.06.1001"; //medansatria, medansatria
} else if($daerah == "depok"){
	$kode_wilayah_tingkat_iv = "32.76.06.1001"; //beji, beji
} else if($daerah == "surabaya"){
	$kode_wilayah_tingkat_iv = "35.78.13.1002"; //bubutan, bubutan
} else if($daerah == "makassar"){
	$kode_wilayah_tingkat_iv = "73.71.04.1008"; //losari, ujung pandang
} else if($daerah == "banjarmasin"){
	$kode_wilayah_tingkat_iv = "63.71.05.1005"; //antasan besar, banjarmasin tengah
} else if($daerah == "aceh"){
	$kode_wilayah_tingkat_iv = "11.71.06.2006"; //gampong jawa, kutaraja
} else if($daerah == "palembang"){
	$kode_wilayah_tingkat_iv = "16.71.13.1005"; //karyajaya, kertapati
} else if($daerah == "manado"){
	$kode_wilayah_tingkat_iv = "71.71.07.1007"; //tingkulu, wanea
} else if($daerah == "papua"){
	$kode_wilayah_tingkat_iv = "93.01.02.2001"; //muting, merauke
} 	


$user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.51",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/109.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:103.0) Gecko/20100101 Firefox/103.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.92 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.196 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; SM-A505F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/17.0 Chrome/96.0.4664.45 Mobile Safari/537.36",
    "Mozilla/5.0 (Android 10; Mobile; rv:102.0) Gecko/102.0 Firefox/102.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/114.0.5735.124 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 15_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/114.0.5735.134 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.100 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Brave/114.1.52.122",
    "Mozilla/5.0 (Linux; Android 11; CPH2083) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Mobile Safari/537.36 OPR/61.1.3076.56626",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36 OPR/100.0.4815.76",
];
$random_user_agent = $user_agents[array_rand($user_agents)];

$url_api_bmkg = "https://api.bmkg.go.id/publik/prakiraan-cuaca?adm4=".$kode_wilayah_tingkat_iv;
$options = array(
  'http'=>array(
	'method'=>"GET",
	'header'=>"Accept-language: en\r\n" .
			  "User-Agent: ".$random_user_agent."\r\n",
	'timeout'=> 3
  )
);
$context = stream_context_create($options);
$results = file_get_contents($url_api_bmkg, false, $context);

if($results != false){
	$arrDataBmkg = json_decode($results, TRUE);
	
	$arrLokasi = isset($arrDataBmkg['lokasi'])?$arrDataBmkg['lokasi']:array();
	$arrCuaca = isset($arrDataBmkg['data'][0]['cuaca'])?$arrDataBmkg['data'][0]['cuaca']:array();
	
	$provinsi = isset($arrLokasi['provinsi'])?$arrLokasi['provinsi']:"";
	$kotkab = isset($arrLokasi['kotkab'])?$arrLokasi['kotkab']:"";
	$kecamatan = isset($arrLokasi['kecamatan'])?$arrLokasi['kecamatan']:"";
	$desa = isset($arrLokasi['desa'])?$arrLokasi['desa']:"";
	$lon = isset($arrLokasi['lon'])?$arrLokasi['lon']:"";
	$lat = isset($arrLokasi['lat'])?$arrLokasi['lat']:"";
	$timezone = isset($arrLokasi['timezone'])?$arrLokasi['timezone']:"";
	
	echo $desa.",".$kecamatan.",".$kotkab.",".$provinsi."<br>";
	echo $lat.",".$lon."<br><br>";
	if(count($arrCuaca)){
		
		foreach($arrCuaca as $id => $rows){
			if($id == 0){
				foreach($rows as $row){
					$local_datetime = $row['local_datetime'];
					$image = $row['image'];
					$t = $row['t'];
					$weather_desc = $row['weather_desc'];
					$hu = $row['hu'];
					$ws = $row['ws'];
					$vs_text = $row['vs_text'];
					
					echo $local_datetime."<br>";
					if(!empty($image)) echo "<img src='".$image."'><br>";
					echo "Suhu Udara : ".$t." <sup>o</sup>C<br>";
					echo "Kondisi Cuaca : ".$weather_desc."<br>";
					echo "Kelembaban Udara : ".$hu."%<br>";
					echo "Kecepatan Angin : ".$ws." km/jam<br>";
					echo "Jarak Pandang : ".$vs_text."<br>";
					
					/* echo "<pre>";
					print_r($row);
					echo "</pre>"; */
					
					echo "<hr>";
				}
			}
		}
	}
}		

echo "\nExecution time in seconds: ". (microtime(true) - $time_start) . "\n";	
?>