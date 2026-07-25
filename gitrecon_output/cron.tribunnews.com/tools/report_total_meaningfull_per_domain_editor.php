<?php
ini_set('display_errors',1);
error_reporting(E_ALL);
//error_reporting(0);
ini_set("memory_limit", "-1");
set_time_limit(0);

$time_start = time();

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."config/other_config.php";
include DOC_ROOT."lib/Opensearch.php";

$tag_alias = isset($_GET['tag'])?$_GET['tag']:"meaningful";
$dateStart = isset($_GET['start'])?$_GET['start']:"";
$dateEnd = isset($_GET['end'])?$_GET['end']:"";

if(empty($dateStart)){	
	$dateStart = date("Y-m-d", strtotime('-1 days'));
}

if(empty($dateEnd)){	
	$dateEnd = date("Y-m-d", strtotime('-1 days'));
}

echo $tag_alias."<br>";
echo $dateStart." - ".$dateEnd."<br><br><br>";


$opensearchAllNetwork = new Opensearch();
$opensearchAllNetwork->init(OS_ALLNETWOORK_URL,OS_ALLNETWOORK_USERNAME,OS_ALLNETWOORK_PASSWORD,true);

$index_name = "tribunnetwork-articles";

$query = [
    'bool' => [
        'filter' => [
            [
                'range' => [
                    'publish_date' => [
                        'gte' => ''.$dateStart.' 00:00:00',
                        'lte' => ''.$dateEnd.' 23:59:59'
                    ]
                ]
            ],
            [
                'nested' => [
                    'path' => 'tagging',
                    'query' => [
                        'term' => [
                            'tagging.alias.keyword' => $tag_alias
                        ]
                    ]
                ]
            ]
        ]
    ]
];
			  

$aggs = [
    'by_domain' => [
        'terms' => [
            'field' => 'domain',
            'size'  => 1000,
			'order' => [
                '_key' => 'asc'
            ]
        ],
        'aggs' => [
            'by_editor' => [
                'terms' => [
                    'field' => 'editor_fullname.keyword',
                    'size'  => 1000,
					 'order' => [
                        '_count' => 'desc' 
                    ]
                ]
            ]
        ]
    ]
];

$response = $opensearchAllNetwork->aggregations($index_name,$aggs,$query);

if($response['status']){
	$rows = isset($response['data']['by_domain']['buckets'])?$response['data']['by_domain']['buckets']:array();
	
	if(count($rows) > 0){
		foreach($rows as $row){
			$domain = $row['key'];
			$total_domain = $row['doc_count'];

			$arrEditor = isset($row['by_editor']['buckets'])?$row['by_editor']['buckets']:array();
			
			echo $domain." = .".$total_domain."<br>";
			if(count($arrEditor) > 0){
				
				foreach($arrEditor as $editor){
					$editor_fullname = $editor['key'];
					$total_editor = $editor['doc_count'];
					
					echo $editor_fullname." = ".$total_editor."<br>";
				}
			}
			
			echo "<hr>";
		}
	}
}	

unset($opensearchAllNetwork);


echo '<br>Execution time in seconds: ' . (microtime(true) - $time_start) . "<br>";
?>