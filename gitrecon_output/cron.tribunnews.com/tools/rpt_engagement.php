<?php
/**
 * CRON — Snapshot Report Like/Dislike/Share (harian)
 * Lokasi saran: cron/tribunnews/report/snapshot_report_likedislike.php
 *
 * Membaca interaksi 1 hari dari interaction_db (content_reactions, content_shares)
 * lalu menulis 3 collection report:
 *   - report_daily_snapshots  (1 dok per domain per hari)
 *   - report_top_content      (1 dok per hari, top 10 lintas domain)
 *   - report_top_user         (1 dok per hari, top 10 reaction + top 10 share)
 *
 * Idempotent: upsert per `date` (+ domain_id utk daily) -> re-run = overwrite.
 *
 * Pemanggilan (via cron / curl):
 *   .../snapshot_report_likedislike.php            -> default H-1
 *   .../snapshot_report_likedislike.php?date=2026-06-16
 *
 * Guard: date >= hari ini ditolak (hanya boleh tanggal yang sudah selesai).
 */

ini_set('display_errors', 1);
error_reporting(E_ALL);

use \MongoDB\BSON\UTCDateTime;

$time_start = microtime(true);

define("DOC_ROOT", "/var/www/html/web-cron/");

require_once DOC_ROOT."vendor/autoload.php";
include DOC_ROOT."config/config.php";
include DOC_ROOT."config/other_config.php";
include DOC_ROOT."lib/Mongodb.php";

// ==========================================================
// DOMAIN MAP (samakan dgn engagement.py) — utk isi field domain string
// ==========================================================
$DOMAIN_MAP = [
    "dev-tnews.tribunnews.com" => 0,
    "tribunnews.com" => 60, "www.tribunnews.com" => 60, "m.tribunnews.com" => 60,
    "jabar.tribunnews.com" => 1, "jakarta.tribunnews.com" => 2, "wartakota.tribunnews.com" => 3,
    "solo.tribunnews.com" => 4, "jogja.tribunnews.com" => 5, "palembang.tribunnews.com" => 6,
    "bali.tribunnews.com" => 7, "aceh.tribunnews.com" => 8, "medan.tribunnews.com" => 9,
    "bangka.tribunnews.com" => 10, "batam.tribunnews.com" => 11, "pekanbaru.tribunnews.com" => 12,
    "sumsel.tribunnews.com" => 13, "lampung.tribunnews.com" => 14, "kupang.tribunnews.com" => 15,
    "banjarmasin.tribunnews.com" => 16, "kaltim.tribunnews.com" => 17, "manado.tribunnews.com" => 18,
    "pontianak.tribunnews.com" => 19, "makassar.tribunnews.com" => 20, "papua.tribunnews.com" => 21,
    "papuabarat.tribunnews.com" => 22, "madura.tribunnews.com" => 23, "surabaya.tribunnews.com" => 24,
    "bogor.tribunnews.com" => 25, "newsmaker.tribunnews.com" => 26, "style.tribunnews.com" => 27,
    "bekasi.tribunnews.com" => 28, "banten.tribunnews.com" => 29, "tangerang.tribunnews.com" => 30,
    "depok.tribunnews.com" => 31, "cirebon.tribunnews.com" => 32, "jateng.tribunnews.com" => 33,
    "banyumas.tribunnews.com" => 34, "pantura.tribunnews.com" => 35, "jatim.tribunnews.com" => 36,
    "suryamalang.tribunnews.com" => 37, "mataraman.tribunnews.com" => 38, "prohaba.tribunnews.com" => 39,
    "sultra.tribunnews.com" => 40, "belitung.tribunnews.com" => 41, "babel.tribunnews.com" => 42,
    "padang.tribunnews.com" => 43, "bengkulu.tribunnews.com" => 44, "jambi.tribunnews.com" => 45,
    "flores.tribunnews.com" => 46, "kalteng.tribunnews.com" => 47, "kaltara.tribunnews.com" => 48,
    "gorontalo.tribunnews.com" => 49, "sulbar.tribunnews.com" => 50, "palu.tribunnews.com" => 51,
    "lombok.tribunnews.com" => 52, "ternate.tribunnews.com" => 53, "ambon.tribunnews.com" => 54,
    "travel.tribunnews.com" => 55, "wow.tribunnews.com" => 56, "video.tribunnews.com" => 57,
    "health.tribunnews.com" => 58, "trends.tribunnews.com" => 59, "shopping.tribunnews.com" => 61,
    "gayo.tribunnews.com" => 62, "muria.tribunnews.com" => 63, "priangan.tribunnews.com" => 64,
    "jatim-timur.tribunnews.com" => 65, "toraja.tribunnews.com" => 66, "booking.tribunnews.com" => 67,
    "sorong.tribunnews.com" => 68, "nanggroe.tribunnews.com" => 69, "papuatengah.tribunnews.com" => 70,
    "mataram.tribunnews.com" => 71,
];

// reverse: domain_id -> domain string (ambil yg pertama match)
$DOMAIN_ID_TO_NAME = [];
foreach ($DOMAIN_MAP as $name => $id) {
    if (!isset($DOMAIN_ID_TO_NAME[$id])) {
        $DOMAIN_ID_TO_NAME[$id] = $name;
    }
}
function domain_name($id) {
    global $DOMAIN_ID_TO_NAME;
    return isset($DOMAIN_ID_TO_NAME[$id]) ? $DOMAIN_ID_TO_NAME[$id] : (string)$id;
}

$PLATFORMS = ["wa", "fb", "twitter", "telegram", "copy"];

// ==========================================================
// 1) RESOLVE TANGGAL + GUARD
// ==========================================================
$date = isset($_GET['date']) ? trim($_GET['date']) : "";
if (empty($date)) {
    $dateStart = date("Y-m-d", strtotime('-1 days')); // default H-1
} else {
    $dateStart = date("Y-m-d", strtotime($date));     // normalisasi format
}

// Guard: tolak kalau >= hari ini
$today = date("Y-m-d");
if ($dateStart >= $today) {
    echo "DITOLAK: tanggal {$dateStart} >= hari ini ({$today}). ";
    echo "Snapshot hanya untuk tanggal yang sudah selesai (maksimal H-1).<br>";
    exit;
}

echo "Generate snapshot untuk tanggal: <b>{$dateStart}</b><br><br>";

// Rentang waktu (pola WIB, sama seperti cron existing)
$start = new UTCDateTime(strtotime($dateStart.' 00:00:00') * 1000 + MONGO_DATETIME_GMT7);
$end   = new UTCDateTime(strtotime($dateStart.' 23:59:59') * 1000 + MONGO_DATETIME_GMT7);

// ==========================================================
// KONEKSI MONGO (interaction_db)
// ==========================================================
$mongodb_options = array(
    'tls' => true,
);

$mongodb = new Mongodb();
$mongodb->connect_replika(
    MONGODB_ENGAGEMENT_HOST,
    MONGODB_ENGAGEMENT_USERNAME,
    MONGODB_ENGAGEMENT_PASSWORD,
    MONGODB_ENGAGEMENT_DBNAME,
    true,
    $mongodb_options
);

// ==========================================================
// 2) DAILY SNAPSHOT PER DOMAIN
// ==========================================================
echo "== Daily snapshot per domain ==<br>";

// --- Reactions per domain ---
$matchReaction = [
    'created_at' => ['$gte' => $start, '$lte' => $end],
    'content_type' => 'article',
];
$optReactionDomain = [
    'group' => [
        '_id' => '$domain_id',
        'likes' => ['$sum' => ['$cond' => [['$eq' => ['$type', 'like']], 1, 0]]],
        'dislikes' => ['$sum' => ['$cond' => [['$eq' => ['$type', 'dislike']], 1, 0]]],
        'contents' => ['$addToSet' => '$content_id'],
    ],
];
$resReaction = $mongodb->aggregate("content_reactions", $matchReaction, $optReactionDomain);

// --- Shares per domain ---
$matchShare = [
    'created_at' => ['$gte' => $start, '$lte' => $end],
    'content_type' => 'article',
];
$shareGroup = [
    '_id' => '$domain_id',
    'shares' => ['$sum' => 1],
    'contents' => ['$addToSet' => '$content_id'],
];
foreach ($PLATFORMS as $p) {
    $shareGroup[$p] = ['$sum' => ['$cond' => [['$eq' => ['$platform', $p]], 1, 0]]];
}
$resShare = $mongodb->aggregate("content_shares", $matchShare, ['group' => $shareGroup]);

// --- Gabung per domain di PHP ---
$domains = []; // domain_id => struct

foreach ($resReaction as $r) {
    $did = $r->_id;
    if (!isset($domains[$did])) {
        $domains[$did] = ['likes' => 0, 'dislikes' => 0, 'shares' => 0,
                          'platforms' => array_fill_keys($PLATFORMS, 0), 'contents' => []];
    }
    $domains[$did]['likes'] = intval($r->likes);
    $domains[$did]['dislikes'] = intval($r->dislikes);
    foreach ((array)$r->contents as $cid) {
        $domains[$did]['contents'][$cid] = true; // set utk unik
    }
}

foreach ($resShare as $s) {
    $did = $s->_id;
    if (!isset($domains[$did])) {
        $domains[$did] = ['likes' => 0, 'dislikes' => 0, 'shares' => 0,
                          'platforms' => array_fill_keys($PLATFORMS, 0), 'contents' => []];
    }
    $domains[$did]['shares'] = intval($s->shares);
    foreach ($PLATFORMS as $p) {
        $domains[$did]['platforms'][$p] = isset($s->$p) ? intval($s->$p) : 0;
    }
    foreach ((array)$s->contents as $cid) {
        $domains[$did]['contents'][$cid] = true;
    }
}

$now = new UTCDateTime(time() * 1000);
$countDomain = 0;

foreach ($domains as $did => $d) {
    $totalLikes = $d['likes'];
    $totalDislikes = $d['dislikes'];
    $totalReactions = $totalLikes + $totalDislikes;
    $totalShares = $d['shares'];
    $totalArticles = count($d['contents']); // unik content_id (union reaction+share)
    $ratio = $totalReactions > 0 ? round($totalLikes / $totalReactions * 100, 1) : 0;

    $doc = [
        'date' => $dateStart,
        'domain_id' => $did,
        'domain' => domain_name($did),
        'total_articles' => $totalArticles,
        'total_likes' => $totalLikes,
        'total_dislikes' => $totalDislikes,
        'total_reactions' => $totalReactions,
        'like_dislike_ratio' => $ratio,
        'total_shares' => $totalShares,
        'shares_by_platform' => $d['platforms'],
        'created_at' => $now,
    ];

    $mongodb->update(
        "report_daily_snapshots",
        ['date' => $dateStart, 'domain_id' => $did],
        ['$set' => $doc],
        true // upsert
    );
    $countDomain++;
}
echo "  -> {$countDomain} domain ter-snapshot<br><br>";

// ==========================================================
// 3) TOP CONTENT (top 10 lintas domain)
// ==========================================================
echo "== Top content ==<br>";

// reactions per (domain_id, content_id)
$optRC = [
    'group' => [
        '_id' => ['domain_id' => '$domain_id', 'content_id' => '$content_id'],
        'likes' => ['$sum' => ['$cond' => [['$eq' => ['$type', 'like']], 1, 0]]],
        'dislikes' => ['$sum' => ['$cond' => [['$eq' => ['$type', 'dislike']], 1, 0]]],
    ],
];
$rcRes = $mongodb->aggregate("content_reactions", $matchReaction, $optRC);

// shares per (domain_id, content_id)
$scGroup = [
    '_id' => ['domain_id' => '$domain_id', 'content_id' => '$content_id'],
    'shares' => ['$sum' => 1],
];
$scRes = $mongodb->aggregate("content_shares", $matchShare, ['group' => $scGroup]);

// merge per key domain_id|content_id
$contentMap = [];
function content_key($did, $cid) { return $did . '|' . $cid; }

foreach ($rcRes as $r) {
    $did = $r->_id->domain_id;
    $cid = $r->_id->content_id;
    $k = content_key($did, $cid);
    if (!isset($contentMap[$k])) {
        $contentMap[$k] = ['domain_id' => $did, 'content_id' => $cid, 'likes' => 0, 'dislikes' => 0, 'shares' => 0];
    }
    $contentMap[$k]['likes'] = intval($r->likes);
    $contentMap[$k]['dislikes'] = intval($r->dislikes);
}
foreach ($scRes as $s) {
    $did = $s->_id->domain_id;
    $cid = $s->_id->content_id;
    $k = content_key($did, $cid);
    if (!isset($contentMap[$k])) {
        $contentMap[$k] = ['domain_id' => $did, 'content_id' => $cid, 'likes' => 0, 'dislikes' => 0, 'shares' => 0];
    }
    $contentMap[$k]['shares'] = intval($s->shares);
}

// hitung total_engagement, urutkan desc, ambil 10
foreach ($contentMap as $k => &$c) {
    $c['total_engagement'] = $c['likes'] + $c['dislikes'] + $c['shares'];
}
unset($c);

usort($contentMap, function ($a, $b) {
    return $b['total_engagement'] - $a['total_engagement'];
});
// search 20
$topContent = array_slice(array_values($contentMap), 0, 20);

// susun items + ambil full_url dari content_stats (boleh kosong)
$contentItems = [];
$rank = 1;
foreach ($topContent as $c) {
    $fullUrl = "";
    $statDoc = $mongodb->findOne(
        "content_stats",
        ['domain_id' => $c['domain_id'], 'content_id' => $c['content_id']],
        ['full_url']
    );
    if ($statDoc && isset($statDoc->full_url)) {
        $fullUrl = $statDoc->full_url;
    }

    $contentItems[] = [
        'rank' => $rank,
        'content_id' => $c['content_id'],
        'content_type' => 'article',
        'domain_id' => $c['domain_id'],
        'domain' => domain_name($c['domain_id']),
        'full_url' => $fullUrl,
        'likes' => $c['likes'],
        'dislikes' => $c['dislikes'],
        'shares' => $c['shares'],
        'total_engagement' => $c['total_engagement'],
    ];
    $rank++;
}

$mongodb->update(
    "report_top_content",
    ['date' => $dateStart],
    ['$set' => ['date' => $dateStart, 'items' => $contentItems, 'created_at' => $now]],
    true
);
echo "  -> " . count($contentItems) . " artikel ter-snapshot<br><br>";

// ==========================================================
// 4) TOP USER (top 10 reaction + top 10 share)
// ==========================================================
echo "== Top user ==<br>";

// top reaction
$optUR = [
    'group' => [
        '_id' => '$user_id',
        'likes' => ['$sum' => ['$cond' => [['$eq' => ['$type', 'like']], 1, 0]]],
        'dislikes' => ['$sum' => ['$cond' => [['$eq' => ['$type', 'dislike']], 1, 0]]],
        'total_reactions' => ['$sum' => 1],
        'user_name' => ['$max' => '$user_name'],
        'full_name' => ['$max' => '$full_name'],
    ],
    'sort' => ['total_reactions' => -1],
    'limit' => 20,
];
$urRes = $mongodb->aggregate("content_reactions", $matchReaction, $optUR);

$topReaction = [];
$rank = 1;
foreach ($urRes as $u) {
    $topReaction[] = [
        'rank' => $rank,
        'user_id' => $u->_id,
        'user_name' => isset($u->user_name) ? $u->user_name : "",
        'full_name' => isset($u->full_name) ? $u->full_name : "",
        'total_reactions' => intval($u->total_reactions),
        'likes' => intval($u->likes),
        'dislikes' => intval($u->dislikes),
    ];
    $rank++;
}

// top share
$usGroup = [
    '_id' => '$user_id',
    'total_shares' => ['$sum' => 1],
    'user_name' => ['$max' => '$user_name'],
    'full_name' => ['$max' => '$full_name'],
];
foreach ($PLATFORMS as $p) {
    $usGroup[$p] = ['$sum' => ['$cond' => [['$eq' => ['$platform', $p]], 1, 0]]];
}
$optUS = [
    'group' => $usGroup,
    'sort' => ['total_shares' => -1],
    'limit' => 20,
];
$usRes = $mongodb->aggregate("content_shares", $matchShare, $optUS);

$topShare = [];
$rank = 1;
foreach ($usRes as $u) {
    $platforms = [];
    foreach ($PLATFORMS as $p) {
        $platforms[$p] = isset($u->$p) ? intval($u->$p) : 0;
    }
    $topShare[] = [
        'rank' => $rank,
        'user_id' => $u->_id,
        'user_name' => isset($u->user_name) ? $u->user_name : "",
        'full_name' => isset($u->full_name) ? $u->full_name : "",
        'total_shares' => intval($u->total_shares),
        'shares_by_platform' => $platforms,
    ];
    $rank++;
}

$mongodb->update(
    "report_top_user",
    ['date' => $dateStart],
    ['$set' => ['date' => $dateStart, 'top_reaction' => $topReaction, 'top_share' => $topShare, 'created_at' => $now]],
    true
);
echo "  -> " . count($topReaction) . " top reaction, " . count($topShare) . " top share<br><br>";

// ==========================================================
// SELESAI
// ==========================================================
$mongodb->close();
unset($mongodb);

$elapsed = microtime(true) - $time_start;
echo "SELESAI untuk {$dateStart}.<br>";
echo "Execution time: " . round($elapsed, 3) . " detik (" . round($elapsed / 60, 2) . " menit)<br>";
?>