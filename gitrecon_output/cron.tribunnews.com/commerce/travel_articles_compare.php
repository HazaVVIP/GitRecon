<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";
include DOC_ROOT."lib/Writelog.php";

$site = "travel";
$dateStart = isset($_GET['start'])?$_GET['start']:"";
$dateEnd = isset($_GET['end'])?$_GET['end']:"";

if(empty($dateStart)){	
	$dateStart = date("Y-m-d", strtotime('-1 days'));
}

if(empty($dateEnd)){	
	$dateEnd = date("Y-m-d", strtotime('-1 days'));
}

echo $site."<br>";
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

$index = $site.".articles";
$opensearch = new Opensearch();
$opensearch->init(OS_COMMERCE_URL,OS_COMMERCE_USERNAME,OS_COMMERCE_PASSWORD,true);
$response_os = $opensearch->count_total($index,$condition);
$totalOs = 0;
if($response_os['status']){
	$totalOs = isset($response_os['total'])?$response_os['total']:0;
} 

//RDS
$con = mysqli_connect(RDS_TBO_HOST,RDS_TBO_USERNAME,RDS_TBO_PASSWORD,$site);
if (mysqli_connect_errno()) {
	echo "Failed to connect to MySQL: " . mysqli_connect_error();
	exit();
}


$arrIDRds = array();
$sql = "SELECT count(a.id) as total
		FROM articles a
		WHERE a.publish_date BETWEEN '".$dateStart." 00:00:00' AND '".$dateEnd." 23:59:59'
		ORDER BY a.id DESC";
$result = mysqli_query($con, $sql);
$rsTotalRds = mysqli_fetch_assoc($result);
$totalRds = isset($rsTotalRds['total'])?$rsTotalRds['total']:0;

echo "Total OS : ".$totalOs."<br>";
echo "Total RDS : ".$totalRds."<br>";

mysqli_free_result($result);
mysqli_close($con);
unset($opensearch);


echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>