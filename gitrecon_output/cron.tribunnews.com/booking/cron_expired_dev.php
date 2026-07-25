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
require_once 'Twilio/autoload.php';

use Twilio\Rest\Client;

$config_db  = new config_db_booking();

$conn       = $config_db->conn_to_db_dev();


$now  = new DateTime();
$mins = $now->getOffset() / 60;
$sgn  = ($mins < 0 ? -1 : 1);
$mins = abs($mins);
$hrs  = floor($mins / 60);
$mins -= $hrs * 60;
$offset = sprintf('%+d:%02d', $hrs * $sgn, $mins);
$conn->query("SET time_zone='$offset';");
$dateNow = $now->format('Y-m-d H:i:s');

$model_transaction = new model_transaction();

$sid             = 'ACa6848a976cce8e42003347139cabf7f7';
$token           = 'ec4446222f3367585d9341af77e5ffbb';
$whatsapp_number = "+6285702280701";
$client          = new Client($sid, $token);

// ✅ Fix 1: Hapus LIMIT 100, proses semua expired sekaligus
$getDataExpired   = $model_transaction->get_invoice_expired($dateNow);
$totalDataExpired = mysqli_num_rows($getDataExpired);

if ($totalDataExpired == 0) {
    echo "No data updated";
    mysqli_close($conn);
    exit;
}

$result = [];
while ($dataEx = mysqli_fetch_assoc($getDataExpired)) {
    $result[] = $dataEx;
}

$waSentInvoices = [];

foreach ($result as $row) {
    $kodeInvoice = $row['kode_invoice'];
    $idTiket     = $row['id_ticket'];
    $idTrx       = $row['id'];

    $conn->begin_transaction();

    try {
        // STEP 1: Kembalikan stock tiket
        // ✅ Fix 3: Atomic update, tidak perlu READ dulu (hindari race condition)
        $sql1 = "UPDATE ticket 
                 SET stock = stock + " . (int)$row['jumlah_ticket'] . " 
                 WHERE id = '$idTiket'";
        if (!$conn->query($sql1)) {
            throw new Exception("Gagal update stock tiket id=$idTiket: " . $conn->error);
        }

        // STEP 2: Kembalikan stock jersey DULU sebelum ubah status
        // ✅ Fix 4: Jersey di-restore sebelum status diubah ke 4
        if (strtolower($row['jersey_type']) === 'fixed') {

            $sqlTicketTrx = "SELECT data_pemesan, id_ticket 
                             FROM tbl_ticket_transaksi 
                             WHERE id_transaksi = '$idTrx' AND is_delete = '0'";
            $resTicketTrx = $conn->query($sqlTicketTrx);

            if (!$resTicketTrx) {
                throw new Exception("Query tbl_ticket_transaksi gagal id_trx=$idTrx: " . $conn->error);
            }

            while ($ticketRow = $resTicketTrx->fetch_assoc()) {
                $dataPemesan   = json_decode($ticketRow['data_pemesan'], true);
                $idTiketJersey = $ticketRow['id_ticket'];

                if (empty($dataPemesan['jersey']) || !is_array($dataPemesan['jersey'])) {
                    continue;
                }

                foreach ($dataPemesan['jersey'] as $jerseyKey => $jerseyVal) {
                    $type   = str_replace("jersey_", "", $jerseyKey);
                    $ukuran = $jerseyVal['ukuran'] ?? '';
                    $jumlah = (int)($jerseyVal['jumlah'] ?? 0);

                    if ($jumlah <= 0 || $ukuran === '') continue;

                    // ✅ Atomic update jersey
                    $sql3 = "UPDATE jersey 
                             SET stock = stock + $jumlah 
                             WHERE id_ticket = '$idTiketJersey' 
                             AND jersey_type = '$type' 
                             AND size = '$ukuran'";
                    if (!$conn->query($sql3)) {
                        throw new Exception("Gagal restore jersey $type $ukuran: " . $conn->error);
                    }

                    error_log("Jersey restored: invoice=$kodeInvoice type=$type size=$ukuran +$jumlah");
                }
            }
        }

        $sql2 = "UPDATE tbl_transaksi 
                 SET status_paid='expire', transaction_status='4' 
                 WHERE id = '$idTrx'";
        if (!$conn->query($sql2)) {
            throw new Exception("Gagal update status id=$idTrx: " . $conn->error);
        }

        $sqlx = "UPDATE tbl_trx_diandra 
                 SET status='0', kode_invoice='', kode_pesan='', 
                     id_tiket='0', created_date=NULL, updated_date=NULL 
                 WHERE kode_invoice='$kodeInvoice'";
        $conn->query($sqlx);

        // Semua berhasil — commit
        $conn->commit();
        error_log("Sukses expire: invoice=$kodeInvoice id_trx=$idTrx");

    } catch (Exception $e) {
        $conn->rollback();
        error_log("ROLLBACK invoice=$kodeInvoice id_trx=$idTrx: " . $e->getMessage());
        continue;
    }

    // STEP 5: Kirim WA — di luar DB transaction, 1x per kode_invoice
    if (!in_array($kodeInvoice, $waSentInvoices)) {
        $waSentInvoices[] = $kodeInvoice;

        $number = (substr($row['phone'], 0, 1) == '0')
            ? '62' . substr($row['phone'], 1)
            : $row['phone'];
        $message    =  'Hi '.$row['nama'].','.PHP_EOL.PHP_EOL;
        $message    .=  'Batas waktu pembayaran untuk transaksi di '.$row['judul'];
        $message    .=  'kamu telah habis.'.PHP_EOL.PHP_EOL;
        $message    .=  'Jika kamu lupa untuk melakukan pembayaran atau ingin membeli tiket event lainnya, kamu bisa melakukan pemesanan tiket kembali, ya!';
        try {
            $client->messages->create(
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
        }
    }
}

mysqli_close($conn);
echo "\nExecution time in seconds: " . (microtime(true) - $time_start) . "\n";
?>