<?php

include_once "/var/www/html/web-cron/config/config.php";
include_once "/var/www/html/web-cron/config/config_db_booking.php";

$config = new config_db_booking();

$conn = $config->conn_to_db_prod();

if ($conn->connect_errno) {
    die("Gagal konek: " . $conn->connect_error);
}

echo "Koneksi Berhasil";