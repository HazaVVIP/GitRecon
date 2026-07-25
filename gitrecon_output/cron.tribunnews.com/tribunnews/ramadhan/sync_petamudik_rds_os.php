<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
ini_set("memory_limit", "-1");
set_time_limit(0);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

//OS
$opensearch = new Opensearch();
$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);


//RDS
$con = mysqli_connect(RDS_HOST,RDS_USERNAME,RDS_PASSWORD,"tribunnews");
if (mysqli_connect_errno()) {
	echo "Failed to connect to MySQL: " . mysqli_connect_error();
	exit();
}

$sql = "SELECT * FROM peta_mudik 
		ORDER BY id ASC";
$result = $result = mysqli_query($con, $sql);
$totalRds = mysqli_num_rows($result);

$totalSyncOs = 0;
if($totalRds > 0){
	while ($row = mysqli_fetch_array($result, MYSQLI_ASSOC)){
		$id = intval($row['id']);
		$province_name = $row['province_name'];
		$province_alias = $row['province_alias'];
		$location_name = $row['location_name'];
		$location_maps = $row['location_maps'];
		$location_tipe = $row['location_tipe'];
		$create_date = $row['create_date'];
		
		$arrInsert = array();
		$arrInsert['id'] = $id;
		$arrInsert['province_name'] = $province_name;
		$arrInsert['province_alias'] = $province_alias;
		$arrInsert['location_name'] = $location_name;
		$arrInsert['location_maps'] = $location_maps;
		$arrInsert['location_tipe'] = $location_tipe;
		$arrInsert['create_date'] = $create_date;
		
		$responseInsertOs = $opensearch->insert("peta_mudik", $arrInsert);
		
		/* echo "<pre>";
		print_r($responseInsertOs);
		print_r($arrInsert);
		echo "</pre>"; */
		
		if($responseInsertOs['status']){
			$totalSyncOs++; 
		}
	}
}

mysqli_free_result($result);

echo "Total SYNC RDS ke OS : ".$totalSyncOs."<br>";

mysqli_close($con);

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>