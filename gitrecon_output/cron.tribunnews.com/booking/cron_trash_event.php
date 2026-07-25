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
$model_transaction  = new model_transaction();
$getTrashEvent      = $model_transaction->get_trash_event();
$totalDataTrash     = mysqli_num_rows($getTrashEvent);
if ($totalDataTrash > 0) {
    $result    = array();
    while ($dataTrash =  mysqli_fetch_assoc($getTrashEvent))
    {
        $result[] = $dataTrash;
    }

    foreach ($result as $row) {
        $idEvent        = $row['id'];
        
        $deleteEvent    = "DELETE FROM `event` WHERE id = '$idEvent'";
        $results1       = $conn->query($deleteEvent);

        $deleteTicekt   = "DELETE FROM `ticket` WHERE id_event= '$idEvent'";
        $results2       = $conn->query($deleteTicekt);

        $deleteCategory = "DELETE FROM `tbl_ticket_category` WHERE id_event= '$idEvent'";
        $results3       = $conn->query($deleteCategory);

        if ($results1 === FALSE || $results2 === FALSE || $results3 === FALSE) {
            die(mysqli_error($conn));
        }
    }
    //mysqli_close($results1);
    //mysqli_close($results2);
}else{
    echo "No data updated";
    exit;
}

mysqli_close($conn);

echo "\nExecution time in seconds: ". (microtime(true) - $time_start) . "\n";

?>