<?php 
ini_set('display_errors',1);
error_reporting(E_ALL);
define('TIMEZONE', 'Asia/Jakarta');
date_default_timezone_set(TIMEZONE);

$time_start = microtime(true);

include "/var/www/html/web-cron/config/config.php";
include_once "/var/www/html/web-cron/booking/model/model_transaction.php";
include_once "/var/www/html/web-cron/config/config_db_booking.php";
require_once 'Twilio/autoload.php';

use Twilio\Rest\Client;
use Twilio\Exceptions\RestException;

$config_db  = new config_db_booking();
$conn       = $config_db->conn_to_db_prod();

$now = new DateTime();
$mins = $now->getOffset() / 60;
$sgn = ($mins < 0 ? -1 : 1);
$mins = abs($mins);
$hrs = floor($mins / 60);
$mins -= $hrs * 60;
$offset = sprintf('%+d:%02d', $hrs*$sgn, $mins);
$conn->query("SET time_zone='$offset';");
$dateNow = $now->format('Y-m-d H:i:s');

$model_transaction = new model_transaction();

$getDataExpired   = $model_transaction->get_invoice_expired($dateNow);
$totalDataExpired = mysqli_num_rows($getDataExpired);

$sid             = 'ACa6848a976cce8e42003347139cabf7f7';
$token           = 'ec4446222f3367585d9341af77e5ffbb';
$whatsapp_number = "+6285702280701";

$client = new Client($sid, $token);

if ($totalDataExpired > 0) {

    $result = [];
    while ($dataEx = mysqli_fetch_assoc($getDataExpired)) {
        $result[] = $dataEx;
    }

    $waSentInvoices = [];

    foreach ($result as $row) {
        $kodeInvoice = $row['kode_invoice'];
        $idTiket     = $row['id_ticket'];
        $idTrx       = $row['id'];

        // 1. Kembalikan stock tiket
        $getStockTicket = $model_transaction->getStockTicket($idTiket);
        $stock          = mysqli_fetch_row($getStockTicket);
        $stockTicket    = (int)$stock[0] + (int)$row['jumlah_ticket'];

        $sql1     = "UPDATE ticket SET stock='$stockTicket' WHERE id='$idTiket'";
        $results1 = $conn->query($sql1);

        // 2. Update status transaksi — gunakan id (PK) bukan kode_invoice
        //    supaya tidak dobel jika 2 row punya kode_invoice sama (Skenario B)
        $sql2     = "UPDATE tbl_transaksi SET status_paid='expire', transaction_status='4' 
                     WHERE id='$idTrx'";
        $results2 = $conn->query($sql2);

        // 3. Reset tbl_trx_diandra
        $sqlx     = "UPDATE tbl_trx_diandra SET `status`='0', kode_invoice='', kode_pesan='', 
                     id_tiket='0', created_date=NULL, updated_date=NULL 
                     WHERE kode_invoice='$kodeInvoice'";
        $resultsx = $conn->query($sqlx);

        if ($results1 === FALSE || $results2 === FALSE) {
            error_log("DB update failed: " . $conn->error);
            continue;
        }

        // 4. Kembalikan stock jersey — hanya jika event jersey_type = 'fixed'
        $results3 = true;

        if (strtolower($row['jersey_type']) === 'fixed') {

            $sqlTicketTrx = "SELECT data_pemesan, id_ticket FROM tbl_ticket_transaksi 
                             WHERE id_transaksi = '$idTrx' AND is_delete = '0'";
            $resTicketTrx = $conn->query($sqlTicketTrx);

            if (!$resTicketTrx) {
                error_log("Query tbl_ticket_transaksi failed: " . $conn->error);
            } else {
                while ($ticketRow = $resTicketTrx->fetch_assoc()) {
                    $dataPemesan   = json_decode($ticketRow['data_pemesan'], true);
                    $idTiketJersey = $ticketRow['id_ticket'];

                    if (empty($dataPemesan['jersey']) || !is_array($dataPemesan['jersey'])) {
                        continue;
                    }

                    foreach ($dataPemesan['jersey'] as $jerseyKey => $jerseyVal) {
                        $type   = str_replace("jersey_", "", $jerseyKey);
                        $ukuran = isset($jerseyVal['ukuran']) ? $jerseyVal['ukuran'] : '';
                        $jumlah = isset($jerseyVal['jumlah']) ? (int)$jerseyVal['jumlah'] : 0;

                        if ($jumlah <= 0 || $ukuran === '') {
                            continue;
                        }

                        $sqlGetJersey = "SELECT stock FROM jersey 
                                         WHERE id_ticket = '$idTiketJersey' 
                                         AND jersey_type = '$type' 
                                         AND `size` = '$ukuran'";
                        $resJersey    = $conn->query($sqlGetJersey);

                        if (!$resJersey) {
                            error_log("getStockJersey failed: " . $conn->error);
                            continue;
                        }

                        $stockJersey = $resJersey->fetch_assoc();

                        if (!$stockJersey) {
                            error_log("Jersey not found: id_ticket=$idTiketJersey type=$type size=$ukuran");
                            continue;
                        }

                        $newStock = (int)$stockJersey['stock'] + $jumlah;

                        $sql3     = "UPDATE jersey SET stock='$newStock' 
                                     WHERE id_ticket='$idTiketJersey' 
                                     AND jersey_type='$type' 
                                     AND `size`='$ukuran'";
                        $results3 = $conn->query($sql3);

                        if ($results3 === FALSE) {
                            error_log("Update jersey failed: " . $conn->error);
                        } else {
                            error_log("Jersey restored: invoice=$kodeInvoice id_ticket=$idTiketJersey type=$type size=$ukuran +$jumlah => $newStock");
                        }
                    }
                }
            }

        } else {
            error_log("Skip jersey restore: invoice=$kodeInvoice jersey_type={$row['jersey_type']}");
        }

        // 5. Kirim WA — 1x per kode_invoice
        if ($results2 && !in_array($kodeInvoice, $waSentInvoices)) {
            $waSentInvoices[] = $kodeInvoice;

            $number = (substr($row['phone'], 0, 1) == '0')
                ? '62' . substr($row['phone'], 1)
                : $row['phone'];
            $message    =  'Hi '.$row['nama'].','.PHP_EOL.PHP_EOL;
            $message    .=  'Batas waktu pembayaran untuk transaksi di '.$row['judul'];
            $message    .=  'kamu telah habis.'.PHP_EOL.PHP_EOL;
            $message    .=  'Jika kamu lupa untuk melakukan pembayaran atau ingin membeli tiket event lainnya, kamu bisa melakukan pemesanan tiket kembali, ya!';

            try {
                $twilio = $client->messages->create(
                    "whatsapp:+" . $number,
                    [
                        "contentSid"       => 'HX45149bd6204d09e50e5188337f8ac290',
                        "from"             => 'whatsapp:' . $whatsapp_number,
                        "contentVariables" => json_encode([
                            "1" => $row['nama'],
                            "2" => $row['judul'],
                        ]),
                    ]
                );
            } catch (RestException $e) {
                error_log("Twilio Error [{$e->getStatusCode()}]: {$e->getMessage()} | number=$number");
                echo $e->getStatusCode() . ': ' . $e->getMessage();
            }
        }
    }

} else {
    echo "No data updated";
    exit;
}

mysqli_close($conn);

echo "\nExecution time in seconds: " . (microtime(true) - $time_start) . "\n";
?>