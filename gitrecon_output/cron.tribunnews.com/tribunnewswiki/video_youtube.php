<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

$time_start = time();

//define("DOC_ROOT","C:\wamp64\www\cron\\");
define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";

//RDS
$con = mysqli_connect(RDS_TNEWSWIKI_HOST,RDS_TNEWSWIKI_USERNAME,RDS_TNEWSWIKI_PASSWORD,"tribunnews");
//$con = mysqli_connect("staging-tribunnews.cttdtdmogujb.ap-southeast-1.rds.amazonaws.com","dbusertnews",'b+!Br9phE4IT+Uz+!!O9rECEXu$Ided#Eki2oZ58',"tribunnews-wiki");
if (mysqli_connect_errno()) {
	echo "Failed to connect to MySQL: " . mysqli_connect_error();
	exit();
}

$channelId = 'UCf_PlMzKoS5-w3BrFsojg5w';
$apikey = 'AIzaSyALPDmWsEect5qvVgcSEx6M6LkN9a4m2pA';
$url = 'https://www.googleapis.com/youtube/v3/search?key='.$apikey.'&channelId='.$channelId.'&part=snippet,id&order=date&maxResults=20';
$content = file_get_contents($url);
$json = json_decode($content,true);
$video_id = "";
foreach($json['items'] as $row){
	$video_id .= $row['id']['videoId'].",";
}	

$data = 0;
if(!empty($video_id)){
	$apikey = 'AIzaSyALPDmWsEect5qvVgcSEx6M6LkN9a4m2pA';
	$url = 'https://www.googleapis.com/youtube/v3/videos?part=snippet&id='.$video_id.'&key='.$apikey;	
	$content = file_get_contents($url);
	$count = 0;
	$json = json_decode($content,true);
	foreach($json['items'] as $row){
		$video_id = $row['id'];
		$title = utf8_encode($row['snippet']['title']);
		$alias = url_title($title,"-",TRUE);
		$description = $row['snippet']['description'];
		$date_publish = date("Y-m-d H:i:s",strtotime((string)$row['snippet']['publishedAt']));
		
		$sql = "SELECT count(video_id) as total FROM video_youtube WHERE video_id = '".$video_id."'"; 
		$resultVideo = mysqli_query($con, $sql);
		$resultVideoYoutube = mysqli_fetch_array($resultVideo, MYSQLI_ASSOC);
		$totalVideo = isset($resultVideoYoutube['total'])?intval($resultVideoYoutube['total']):0;	

		if($totalVideo < 1){
			$file = '{"youtube":{"id":"'.$video_id.'"}}';
			$dataVideo = array('title' => utf8_encode($title),
								'alias' => $alias,
								'topic' => '',
								'file' => $file,
								'poster' => $video_id,
								'fulltexts' => $description,
								'uploader_source' => '0',
								'uploader' => '0',
								'editor_video' => '0',
								'reporter' => '0',
								'cameraman' => '0',
								'source' => '0',
								'upload_date' => $date_publish,
								'publish_date' => $date_publish,
								'publish' => '0',
								'category' => 'news',
								'duration' => NULL,
								'transcoder_jobid' => NULL,
								'brightcove_id' => NULL,
								'mivo_id' => NULL,
								'views ' => '0'
						);
									
			$sqlInsert = "INSERT INTO video (title,alias,topic,file,poster,fulltexts,uploader_source,uploader,editor_video,reporter,cameraman,source,upload_date,publish_date,publish,category,duration,transcoder_jobid,brightcove_id,mivo_id,views)
			VALUES ('".mysqli_real_escape_string($con,$title)."', '".$alias."', '', '".$file."', '".$video_id."', '".mysqli_real_escape_string($con,$description)."', '0', '0', '0', '0', '0', '0', '".$date_publish."', '".$date_publish."', '0', 'news', NULL, NULL, NULL, NULL, '0')";
			$insertVideo = mysqli_query($con, $sqlInsert);
			$id = mysqli_insert_id($con);
			
			if (!$insertVideo) {
				echo $sqlInsert."<br>";
				printf("Error message: %s\n", mysqli_error($con));
			}

			if(!empty($id)){
				$count = $count+1;
				$data = $count;
				
				$sqlInsertDetail = "INSERT INTO video_youtube (video_id) VALUES ('".$video_id."')";
				$insertVideoYoutube = mysqli_query($con, $sqlInsertDetail);
				$video_youtube_id = mysqli_insert_id($con);
			} else {
				$data = $count;
			}	
		} else{
			$data = $count;
		}	
	}
}	

mysqli_close($con);

echo date("d-M-Y H:i:s")."<br>";
echo "Total = ".$data."<br>";
echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";

function url_title($str) {
	 $title = strtolower(trim($str));
	 $replacements = ['@'=> "at", '#' => "hash", '$' => "dollar", '%' => "percentage", '&' => "and", '.' => "dot", 
				'+' => "plus", '-' => "minus", '*' => "multiply", '/' => "devide", '=' => "equal to",
				'<' => "less than", '<=' => "less than or equal to", '>' => "greater than", '<=' => "greater than or equal to",
		];

	 $title = strtr($title, $replacements);
	 return $urlKey = preg_replace('#[^0-9a-z]+#i', '-', $title);
}
?>