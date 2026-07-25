<?php 
ini_set('display_errors',1);
error_reporting(E_ALL);
define('TIMEZONE', 'Asia/Jakarta');
date_default_timezone_set(TIMEZONE);
//error_reporting(0);

$time_start = time();

include "/var/www/html/web-cron/config/config.php";
include_once "/var/www/html/web-cron/booking/model/model_transaction.php";
include_once "/var/www/html/web-cron/config/config_db_booking.php";

$config_db  = new config_db_booking();

$conn       = $config_db->conn_to_db_prod();
//load model class

$startDate = date('Y-m-d', strtotime('-1 month'));
$endDate = date('Y-m-d');
$today = date('Y-m-d');

$sqlQuery = "SELECT * FROM log_query WHERE created_at BETWEEN '$startDate' AND '$endDate'";

$result = mysqli_query($conn, $sqlQuery);

$fileName = "log_data_tbooking_$today.sql";
$fileHandle = fopen($fileName, 'w');

if ($fileHandle) {
    while ($row = mysqli_fetch_assoc($result)) {
        $insertStatement = "INSERT INTO log_query (log_query, table_name, created_at,user_id,ip_address,id_event,method) VALUES ('" . $row['log_query'] . "', '" . $row['table_name'] . "', '" . $row['created_at'] . "','" . $row['user_id'] . "','" . $row['ip_address'] . "','" . $row['id_event'] . "','" . $row['method'] . "');";
        fwrite($fileHandle, $insertStatement . PHP_EOL);
    }

    fclose($fileHandle);

    echo "Data exported successfully to $fileName";
} else {
    echo "Error creating $fileName";
}

mysqli_close($conn);

echo "\nExecution time in seconds: ". (microtime(true) - $time_start) . "\n";

?>