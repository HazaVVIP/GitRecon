<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";

$api_key = YOUTUBE_KEY;
$channelId = YOUTUBE_CHANNEL_ID; /* Check if video from channel tribunnews */

//RDS
$con = mysqli_connect(RDS_HOST_MASTER,RDS_USERNAME_MASTER,RDS_PASSWORD_MASTER,"tribunnews");
if (mysqli_connect_errno()) {
	echo "Failed to connect to MySQL: " . mysqli_connect_error();
	exit();
}

$max = 10;
$apierror = 'Not found';
$videolist = array();
$total = 0;

try{
	$apiUrl = 'https://www.googleapis.com/youtube/v3/search?part=id,snippet&channelId='.$channelId.'&key='.$api_key.'&order=date&maxResults='.$max.'&type=video&videoDuration=short';
	$opts = array(
			'http'=>array(
				'method'=>"GET",
				'timeout' => 5,
				'header'=>"Accept-language: en\r\n"
			),
			'ssl'  => array (
				'verify_peer'      => false,
				'verify_peer_name' => false,
			  )
			);
	$context = stream_context_create($opts);
	$apiData = @file_get_contents($apiUrl, false, $context);

	if($apiData === FALSE) {	
	
	} else {
		$videolist = json_decode($apiData);
	}
}catch(Exception $e){
	$apierror = $e->getMessage();
}

if(@count($videolist) > 0){
	$sqlVideo = "SELECT url
			FROM frontpage_publish
			WHERE type = 'video-short'
			ORDER BY id DESC
			LIMIT 20";
	$resultVideo = mysqli_query($con, $sqlVideo);
	$totalVideo = mysqli_num_rows($resultVideo);

	$arrYoutubeID = array();
	if($totalVideo > 0){
		while($youtube_embed = mysqli_fetch_assoc($resultVideo))
		{
			$youtube_video_url = isset($youtube_embed['url'])?$youtube_embed['url']:"";
			
			if(!empty($youtube_video_url)){
				preg_match("/(?:https?:\/\/)?(?:www\.)?(?:m\.)?(?:youtu\.be\/|youtube\.com\/(?:(?:watch)?\?(?:\S*&)?vi?=|(?:embed|v|vi|user|shorts)\/))([^?&\"'>\s]+)/",$youtube_video_url,$match);
				$youtube_video_id = isset($match[1])?$match[1]:"";

				if(!empty($youtube_video_id)) array_push($arrYoutubeID, $youtube_video_id);
			}
		}	
	}
	
	$items = isset($videolist->items)?$videolist->items:array();
	if(count($items) > 0){
		foreach($items as $i => $row){
			$youtube_id = $row->id->videoId;
			$youtube_etag= $row->etag;
			$youtube_live_broadcast = $row->snippet->liveBroadcastContent;
			$youtube_short_url = "https://www.youtube.com/shorts/".$youtube_id;
			
			if(!in_array($youtube_id, $arrYoutubeID) && $youtube_live_broadcast == "none"){
				$youtube_title = isset($row->snippet->title)?$row->snippet->title:"";
				$youtube_title = utf8_encode(trim($youtube_title));
				$youtube_title = preg_replace('/[^(\x20-\x7F)]*/','', $youtube_title);
				$youtube_title = str_replace("'","\'",$youtube_title);
				$youtube_description = isset($row->snippet->description)?$row->snippet->description:"";
				
				//if (strpos($youtube_description, "...") !== false) {
					$opts = stream_context_create(array('http'=>
								array(
									'timeout' => 3,
								)
							));
					$response = @file_get_contents($youtube_short_url, false, $opts);
					$http_code = "";
					$status_response_header = isset($http_response_header[0])?$http_response_header[0]:"";
					if(!empty($status_response_header)){
						preg_match('{HTTP\/\S*\s(\d{3})}', $status_response_header, $match);
						$http_code = isset($match[1])?$match[1]:"";
					}

					if($http_code == 200){
						if($youtube_title != 'Private video' && $youtube_title != 'Deleted video'){
							$youtube_short_url = str_replace("https://www.youtube.com/shorts/","https://youtu.be/",$youtube_short_url);
							
							$sql = "INSERT into frontpage_publish SET 
										type = 'video-short',
										article_id = 0,
										order_by = 0,
										url = '".$youtube_short_url."', 
										url_title = '".$youtube_title."'";

							if (!mysqli_query($con, $sql)) {
								printf("Error message: %s\n", mysqli_error($con));
							} else {
								$id = mysqli_insert_id($con);

								$total++; 
							}
						}
					}
				//}	
			}
		}	
	}	
}

echo "Total : ".$total."<br>";

mysqli_close($con);

echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>