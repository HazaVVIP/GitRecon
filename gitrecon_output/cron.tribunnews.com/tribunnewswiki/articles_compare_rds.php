<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
ini_set("memory_limit", "-1");
set_time_limit(0);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$dateStart = isset($_GET['start'])?$_GET['start']:"";
$dateEnd = isset($_GET['end'])?$_GET['end']:"";

if(empty($dateStart)){	
	$dateStart = date("Y-m-d", strtotime('-1 days'));
}

if(empty($dateEnd)){	
	$dateEnd = date("Y-m-d", strtotime('-1 days'));
}

echo $dateStart." - ".$dateEnd."<br>";

//RDS
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

$conTnews = mysqli_connect('db-dev8.cuhyfpzt6xd5.ap-southeast-1.rds.amazonaws.com','dev-cms','ju8tldacH3zIjejopHowrOfUt7aSiziBrOtlpRec','tribunnews');
if (mysqli_connect_errno()) {
	echo "Failed to connect to MySQL: " . mysqli_connect_error();
	exit();
}


$con = mysqli_connect(RDS_TNEWSWIKI_HOST,RDS_TNEWSWIKI_USERNAME,RDS_TNEWSWIKI_PASSWORD,"tribunnews");
if (mysqli_connect_errno()) {
	echo "Failed to connect to MySQL: " . mysqli_connect_error();
	exit();
}

$sql = "SELECT count(id) as total FROM articles 
		WHERE 
		publish_date BETWEEN '".$dateStart." 00:00:00' AND '".$dateEnd." 23:59:59'";
$result = $result = mysqli_query($con, $sql);
$row = mysqli_fetch_array($result, MYSQLI_ASSOC);
$totalRds = isset($row['total'])?$row['total']:0;

mysqli_free_result($result);

mysqli_close($con);
mysqli_close($conTnews);

echo "RDS Total : ".$totalRds."<br>";


//OS	
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
$opensearch = new Opensearch();
$opensearch->init(OS_TNEWSWIKI_URL,OS_TNEWSWIKI_USERNAME,OS_TNEWSWIKI_PASSWORD,true);
$response = $opensearch->count_total('tribunnewswiki-articles',$condition);

$totalOs = 0;
if($response['status']){
	$totalOs = isset($response['total'])?$response['total']:0;
}

echo "OS Total : ".$totalOs."<br>";

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>