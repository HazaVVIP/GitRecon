<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
//error_reporting(0);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/simple_html_dom.php";
include DOC_ROOT."lib/Opensearch.php";

/* 
Running in command
- sudo -u www-data /usr/bin/php7.4 /var/www/html/web-cron/tribunnews/topskorassist_transfermarkt.php inggris
*/


$liga = isset($_SERVER["argv"][1])?$_SERVER["argv"][1]:"";
if(isset($_GET['liga'])){
	$liga = $_GET['liga'];
}	

$totalUpdate = 0;

$url_topskor = "https://www.transfermarkt.co.id/serie-a/torschuetzenliste/wettbewerb/IT1/saison_id/2025";
$url_assist = "https://www.transfermarkt.co.id/serie-a/assistliste/wettbewerb/IT1/saison_id/2025";
if($liga == "inggris"){
	$url_topskor = "https://www.transfermarkt.co.id/premier-league/torschuetzenliste/wettbewerb/GB1/saison_id/2025";
	$url_assist = "https://www.transfermarkt.co.id/premier-league/assistliste/wettbewerb/GB1/saison_id/2025";
} else if($liga == "italia"){
	$url_topskor = "https://www.transfermarkt.co.id/serie-a/torschuetzenliste/wettbewerb/IT1/saison_id/2025";
	$url_assist = "https://www.transfermarkt.co.id/serie-a/assistliste/wettbewerb/IT1/saison_id/2025";
} else if($liga == "prancis"){
	$url_topskor = "https://www.transfermarkt.co.id/ligue-1/torschuetzenliste/wettbewerb/FR1/saison_id/2025";
	$url_assist = "https://www.transfermarkt.co.id/ligue-1/assistliste/wettbewerb/FR1/saison_id/2025";
} else if($liga == "spanyol"){
	$url_topskor = "https://www.transfermarkt.co.id/laliga/torschuetzenliste/wettbewerb/ES1/saison_id/2025";
	$url_assist = "https://www.transfermarkt.co.id/laliga/assistliste/wettbewerb/ES1/saison_id/2025";
} else if($liga == "jerman"){
	$url_topskor = "https://www.transfermarkt.co.id/bundesliga/torschuetzenliste/wettbewerb/L1/saison_id/2025";
	$url_assist = "https://www.transfermarkt.co.id/bundesliga/assistliste/wettbewerb/L1/saison_id/2025";
} else if($liga == "indonesia"){
	$url_topskor = "https://www.transfermarkt.co.id/liga-1-indonesia/torschuetzenliste/wettbewerb/IN1L/saison_id/2025";
	$url_assist = "https://www.transfermarkt.co.id/liga-1-indonesia/assistliste/wettbewerb/IN1L/saison_id/2025";
} else if($liga == "champions"){
	$url_topskor = "https://www.transfermarkt.co.id/uefa-champions-league/torschuetzenliste/pokalwettbewerb/CL/saison_id/2025";
	$url_assist = "";
} else if($liga == "europa"){
	$url_topskor = "https://www.transfermarkt.co.id/europa-league/torschuetzenliste/pokalwettbewerb/EL";
	$url_assist = "";
} 

$arrFindClub = array("Manchester City","Brentford FC","Chelsea FC","Brighton & Hove Albion","Liverpool FC","Arsenal FC","Fulham FC","Tottenham Hotspur","AFC Bournemouth","West Ham United","Sunderland AFC","Everton FC","Burnley FC","Nottingham Forest",
"Como 1907","Juventus FC","Udinese Calcio","SSC Napoli","Atalanta BC","US Sassuolo","Torino FC","Parma Calcio 1913","ACF Fiorentina","Hellas Verona","US Cremonese","Bologna FC 1909","AS Roma","Cagliari Calcio",
"RC Strasbourg Alsace","Olympique Marseille","RC Lens","Olympique Lyon","AS Monaco","Paris Saint-Germain","FC Toulouse","Stade Brestois 29","FC Lorient","LOSC Lille","Stade Rennais FC",
"FC Barcelona","RCD Mallorca","CA Osasuna","Celta de Vigo","Deportivo Alavés","Atlético de Madrid","Villarreal CF","Girona FC","Valencia CF","Real Betis Balompié","Elche CF","RCD Espanyol Barcelona","Sevilla FC",
"Bayern Munich","VfB Stuttgart","Borussia Dortmund","Borussia Mönchengladbach","TSG 1899 Hoffenheim");

$arrReplClub = array("Man. City","Brentford","Chelsea","Brighton","Liverpool","Arsenal","Fulham","Tottenham","Bournemouth","West Ham","Sunderland","Everton","Burnley","Nottm Forest",
"Como","Juventus","Udinese","Napoli","Atalanta","Sassuolo","Torino","Parma","Fiorentina","Verona","Cremonese","Bologna","Roma","Cagliari",
"Strasbourg","Marseille","Lens","Lyon","Monaco","Paris SG","Toulouse","Brest","Lorient","Lille","Rennes",
"Barcelona","Mallorca","Osasuna","Celta Vigo","Alaves","Atlético Madrid","Villarreal","Girona","Valencia","Betis","Elche","Espanyol","Sevilla",
"Bayern","Stuttgart","Dortmund","Mönchengladbach","Hoffenheim");

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
	"timeout" => 2
  )
);

$context = stream_context_create($options);
$results = @file_get_contents($url_topskor, false, $context);

echo $url_topskor."<br><br>";

if($results != false){
	$dom = new DOMDocument('1.0', 'UTF-8');
	$dom->preserveWhiteSpace = false; 
	@$dom->loadHTML($results);
	
	$xpath = new DOMXPath($dom);
	
	$rows = $xpath->query("//table[contains(@class,'items')]/tbody/tr");
	
	foreach ($rows as $row) {
		$nameNode = $xpath->query(".//td[contains(@class,'hauptlink')]/a", $row);
		$name = $nameNode->length ? trim($nameNode->item(0)->textContent) : '';

		$club = '';
		$clubImg = $xpath->query(".//td[a[contains(@href,'/verein/')]]//img", $row);
		if($clubImg->length){
			$club = trim($clubImg->item(0)->getAttribute("alt"));
		}

		if(empty($club)){
			$clubText = $xpath->query(".//td[a[contains(@href,'/verein/')]]/a", $row);
			if($clubText->length){
				$club = trim($clubText->item(0)->textContent);
			}
		}

		$goalNode = $xpath->query(".//td[contains(@class,'zentriert')][last()]", $row);
		$goals = $goalNode->length ? intval(trim($goalNode->item(0)->textContent)) : 0;

		if(!empty($name) && !empty($club) && !empty($goals)){
			$club = str_replace($arrFindClub,$arrReplClub,$club);
			
			echo "Nama  : $name <br>";
			echo "Klub  : $club <br>";
			echo "Gol   : $goals <br>";
			echo "<hr>";
		}
	}
}	


if(!empty($url_assist)){
	echo $url_assist."<br><br>";

	$results1 = @file_get_contents($url_assist, false, $context);

	if($results1 != false){
		$dom1 = new DOMDocument('1.0', 'UTF-8');
		$dom1->preserveWhiteSpace = false; 
		@$dom1->loadHTML($results1);
		
		$xpath1 = new DOMXPath($dom1);
		
		$rows = $xpath1->query("//table[contains(@class,'items')]/tbody/tr");
		
		foreach ($rows as $row) {
			$nameNode = $xpath1->query(".//td[contains(@class,'hauptlink')]/a", $row);
			$name = $nameNode->length ? trim($nameNode->item(0)->textContent) : '';

			$club = '';
			$clubImg = $xpath1->query(".//td[a[contains(@href,'/verein/')]]//img", $row);
			if($clubImg->length){
				$club = trim($clubImg->item(0)->getAttribute("alt"));
			}

			if(empty($club)){
				$clubText = $xpath1->query(".//td[a[contains(@href,'/verein/')]]/a", $row);
				if($clubText->length){
					$club = trim($clubText->item(0)->textContent);
				}
			}

			$goalNode = $xpath1->query(".//td[contains(@class,'zentriert')][last()]", $row);
			$assists = $goalNode->length ? intval(trim($goalNode->item(0)->textContent)) : 0;

			if(!empty($name) && !empty($club) && !empty($assists)){
				$club = str_replace($arrFindClub,$arrReplClub,$club);
				
				echo "Nama  	: $name <br>";
				echo "Klub  	: $club <br>";
				echo "Assist   	: $assists <br>";
				echo "<hr>";
			}
		}
	}	
}

echo "\nExecution time in seconds: ". (microtime(true) - $time_start) . "\n";
?>