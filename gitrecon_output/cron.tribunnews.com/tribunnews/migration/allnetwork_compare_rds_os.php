<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."config/other_config.php";
include DOC_ROOT."lib/Opensearch.php";

$domain = isset($_GET['domain'])?$_GET['domain']:"depok";
$dateStart = isset($_GET['start'])?$_GET['start']:"";
$dateEnd = isset($_GET['end'])?$_GET['end']:"";

if(empty($dateStart)){	
	$dateStart = date("Y-m-d", strtotime('-1 days'));
}

if(empty($dateEnd)){	
	$dateEnd = date("Y-m-d", strtotime('-1 days'));
}

echo $domain."<br>";
echo $dateStart." - ".$dateEnd."<br>";

$opensearchAllNetwork = new Opensearch();
$opensearchAllNetwork->init(OS_ALLNETWOORK_URL,OS_ALLNETWOORK_USERNAME,OS_ALLNETWOORK_PASSWORD,true);

$where = array();
array_push($where,array("range" => array("publish_date" => array("gte" => ''.$dateStart.' 00:00:00', "lte" => ''.$dateEnd.' 23:59:59'))));	
array_push($where,array("match_phrase" => array("domain" => $domain)));
array_push($where,array("terms" => array("content_status" => array(1,2))));

$condition = array();
if(count($where) > 0){
	$condition = array("bool" =>
					array("must" =>
						$where
					)
				);
}
$index = "tribunnetwork-articles";
$response_os_allnetwork = $opensearchAllNetwork->count_total($index,$condition);	

$totalOsAllNetwork = 0;
if($response_os_allnetwork['status']){
	$totalOsAllNetwork = isset($response_os_allnetwork['total'])?$response_os_allnetwork['total']:0;
} 

echo "Total OS All Network : ".$totalOsAllNetwork."<br>";


unset($opensearchAllNetwork);


/////////////////////////


//RDS
if($domain == "tribunnews"){
	$con = mysqli_connect(RDS_HOST,RDS_USERNAME,RDS_PASSWORD,"tribunnews");
} else {
	$domainRds = str_replace("aceh","aceh2",$domain);
	$domainRds = str_replace("jambi","jambi2",$domainRds);
	
	if(in_array($domain, LIST_COMMERCE_CLUSTER)){
		$con = mysqli_connect(RDS_TBO_HOST,RDS_TBO_USERNAME,RDS_TBO_PASSWORD,$domainRds);
	} else if(in_array($domain, LIST_TBO_CLUSTER)){
		$con = mysqli_connect(RDS_TBO_HOST,RDS_TBO_USERNAME,RDS_TBO_PASSWORD,$domainRds);
	} else if(in_array($domain, LIST_DAERAH_NEW)){
		$con = mysqli_connect(RDS_DAERAH_HOST,RDS_DAERAH_USERNAME,RDS_DAERAH_PASSWORD,$domainRds);
	} else if(in_array($domain, LIST_DAERAH_CLUSTER)){
		$con = mysqli_connect(RDS_DAERAH_NEW_HOST,RDS_DAERAH_NEW_USERNAME,RDS_DAERAH_NEW_PASSWORD,$domainRds);
	} else { 
		$con = mysqli_connect(RDS_DAERAH_HOST,RDS_DAERAH_USERNAME,RDS_DAERAH_PASSWORD,$domainRds);
	}
}	
if (mysqli_connect_errno()) {
	echo "Failed to connect to MySQL: " . mysqli_connect_error();
	exit();
}

$totalRds = 0;
$arrIDRds = array();
$sql = "SELECT count(a.id) as total
		FROM articles a
	    WHERE a.publish_date BETWEEN '".$dateStart." 00:00:00' AND '".$dateEnd." 23:59:59'
	    ORDER BY a.id DESC";
$result = mysqli_query($con, $sql);
$rsTotalRds = mysqli_fetch_assoc($result);
$totalRds = isset($rsTotalRds['total'])?$rsTotalRds['total']:0;

echo "Total RDS : ".$totalRds."<br>";

mysqli_free_result($result);
mysqli_close($con);

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>