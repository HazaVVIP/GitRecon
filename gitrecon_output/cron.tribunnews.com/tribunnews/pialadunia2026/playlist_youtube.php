<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
ini_set("memory_limit", "-1");
set_time_limit(0);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$playlist_name = isset($_SERVER["argv"][1])?$_SERVER["argv"][1]:"";
if(isset($_GET['playlist_name'])){
	$playlist_name = $_GET['playlist_name'];
}	

$arrPlaylist = array(
					array("playlist_name"=> "superskor", "playlist_id"=> "PLRUmxnvpvtsss1nsTM8OAt9dZyEXy4pt4")
				);
				

$arrayKey = searcharray($playlist_name, "playlist_name", $arrPlaylist);

$videoList = array();

$channelId = 'UCmxAIW7RDDC88EPk4ry16Kg';
$apiKey = 'AIzaSyCZHyglyvDMfdXrlc6oUYzZnTdMrMBEh5I';
$max = 20;

$playlistId = isset($arrPlaylist[$arrayKey]['playlist_id'])?$arrPlaylist[$arrayKey]['playlist_id']:"";

if(!empty($playlistId)){
	$apiv3_getPlaylist = 'https://www.googleapis.com/youtube/v3/playlistItems?part=snippet&channelId='.$channelId.'&key='.$apiKey.'&playlistId='.$playlistId.'&maxResults='.$max.'&order=viewcount&type=video';
	
	$apierror = 'Not found';
	try{
		$apiData = @file_get_contents($apiv3_getPlaylist);
		
		if($apiData){
			$jsonVideoList = json_decode($apiData, TRUE);
			
			$videoList = isset($jsonVideoList['items'])?$jsonVideoList['items']:array();
		}else{
			throw new Exception('Invalid API Key or Channel ID');
		}
	}catch(Exception $e){
		$apierror = $e->getMessage();
	}
}	


//print_r($videoList);

$arrSuperskor = array();
if(count($videoList) > 0){
	//OS
	//$opensearchDev = new Opensearch();
	//$opensearchDev->init(OS_DEV_URL,OS_DEV_USERNAME,OS_DEV_PASSWORD,true);
	
	$opensearch = new Opensearch();
	$opensearch->init(OS_TBO_URL,OS_TBO_USERNAME,OS_TBO_PASSWORD,true);
	
	foreach($videoList as $k => $video){
		if(@$video['snippet']['title'] == 'Private video'){
			continue;
		}

		$id = $k+1;
		$title = @$video['snippet']['title'];
		$title = utf8_encode($title);
		$title = preg_replace('/[^(\x20-\x7F)]*/','', $title);
		$title = str_replace("'","\'",$title);
		$title = trim($title);
		$description = @$video['snippet']['description'];
		$description = html_entity_decode(str_replace("'","\'",$description), ENT_QUOTES, "UTF-8");
		$published_at = date("Y-m-d H:i:s",strtotime((string)$video['snippet']['publishedAt']));
		$youtube_video_id = @$video['snippet']['resourceId']['videoId'];
		
		$arrSuperskor[$k]['id'] = $arrPlaylist[$arrayKey]['playlist_name']."-".$id;
		$arrSuperskor[$k]['youtube_video_id'] = $youtube_video_id;
		$arrSuperskor[$k]['title'] = $title;
		$arrSuperskor[$k]['alias'] = url_title($title);
		$arrSuperskor[$k]['description'] = $description;
		$arrSuperskor[$k]['published_at'] = $published_at;
		$arrSuperskor[$k]['playlist_id'] = $arrPlaylist[$arrayKey]['playlist_id'];
		$arrSuperskor[$k]['playlist_name'] = ucwords(str_replace(array("-"),array(" "),$arrPlaylist[$arrayKey]['playlist_name']));
		$arrSuperskor[$k]['playlist_alias'] = $arrPlaylist[$arrayKey]['playlist_name'];
		$arrSuperskor[$k]['create_date'] = date("Y-m-d H:i:s");
		
		$arrInsert = array();
		$arrInsert['id'] = $arrPlaylist[$arrayKey]['playlist_name']."-".$id;
		$arrInsert['youtube_video_id'] = $youtube_video_id;
		$arrInsert['title'] = $title;
		$arrInsert['alias'] = url_title($title);
		$arrInsert['description'] = $description;
		$arrInsert['published_at'] = $published_at;
		$arrInsert['playlist_id'] = $arrPlaylist[$arrayKey]['playlist_id'];
		$arrInsert['playlist_name'] = ucwords(str_replace(array("-"),array(" "),$arrPlaylist[$arrayKey]['playlist_name']));
		$arrInsert['playlist_alias'] = $arrPlaylist[$arrayKey]['playlist_name'];
		$arrInsert['create_date'] = date("Y-m-d H:i:s");
		
		$responseInsertOs = $opensearch->insert("playlist_youtube_superskor", $arrInsert);
		
		echo "<pre>";
		print_r($responseInsertOs);
		print_r($arrInsert);
		echo "</pre>";
	}	
	
	//unset($opensearchDev);
	unset($opensearch);
}


/* echo "<pre>";
print_r($arrSuperskor);
echo "</pre>"; */

function searcharray($value, $key, $array) {
	foreach ($array as $k => $val) {
		if ($val[$key] == $value) {
		   return $k;
		}
	}
	return null;
}

function url_title($str, $separator = '-', $lowercase = TRUE)
{
	if ($separator == 'dash') 
	{
		$separator = '-';
	}
	else if ($separator == 'underscore')
	{
		$separator = '_';
	}
	
	$q_separator = preg_quote($separator);

	$trans = array(
		'&.+?;'                 => '',
		'[^a-z0-9 _-]'          => '',
		'\s+'                   => $separator,
		'('.$q_separator.')+'   => $separator
	);

	$str = strip_tags($str);

	foreach ($trans as $key => $val)
	{
		$str = preg_replace("#".$key."#i", $val, $str);
	}

	if ($lowercase === TRUE)
	{
		$str = strtolower($str);
	}

	return trim($str, $separator);
}

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>
