<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
ini_set('memory_limit', '-1');
set_time_limit(0); 

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";
include DOC_ROOT."lib/aws/aws-autoloader.php";
include DOC_ROOT."lib/Helper.php";
include DOC_ROOT."lib/Storage.php";
include DOC_ROOT."lib/UploadManager.php";
include DOC_ROOT."lib/Logger.php";

$url = isset($_GET["url"])?$_GET["url"]:"";

if (empty($url)) {
    echo "Usage: php get_detail.php <url>\n";
    exit(1);
}

$parsedUrl = parse_url($url);
$host = isset($parsedUrl['host']) ? $parsedUrl['host'] : '';
$alias = isset($parsedUrl['path']) ? $parsedUrl['path'] : '';

$domain = '';
if (!empty($host)) {
    $hostParts = explode('.', $host);
    if (count($hostParts) > 2) {
        $domain = $hostParts[0]; 
    }
}

if(!empty($domain) && !empty($alias)){
	if($domain == "www" || $domain == "m") $domain = "tribunnews";
	$domain = str_replace("jatim-timur","jatimtimur",$domain);
	
	$file_alias = $alias.".json";
	$key = $domain.$file_alias;
		
	$storage       = new Storage(STORAGE_DRIVER, S3_BUCKET);
	$article_exists = $storage->exists($key);
	
	echo $key."<br>";
	if($article_exists){
		$article = $storage->read($key);
		
		$article_static_url = $storage->getUrl($key);
		
		echo $article_static_url."<br>";
		echo "<pre>";
		print_r($article);
		echo "</pre>";
	} else {
		die('json file not exits');
	}	
}

?>