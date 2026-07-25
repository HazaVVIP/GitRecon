<?php
ini_set('display_errors',1);
error_reporting(E_ALL);

define("DOC_ROOT","/var/www/html/web-cron/");

include DOC_ROOT."config/config.php";
include DOC_ROOT."lib/Opensearch.php";

$site = "health";

if(!empty($site)){
	$opensearch = new Opensearch();
	$opensearch->init(OS_COMMERCE_URL,OS_COMMERCE_USERNAME,OS_COMMERCE_PASSWORD,true);
	
	$index = $site.".articles";
	$tables = array(
			'id' => "integer",
			'title' => "text",
			'alias' => "text_keyword",
			"subtitle" => "text_keyword", 
			"subtitle_alias" => "keyword",
			"foto_type" => "text_keyword",
			"foto_name" => "text_keyword",
			"foto_caption" => "text_keyword",
			"foto_source" => "text_keyword",
			"foto_position" => "text_keyword",
			"introtext" => "text_keyword",
			"fulltexts" => "text",
			"section_id" => "integer",
			"category_id" => "integer",
			"publish" => "integer",
			"frontpage_section" => "integer",
			"frontpage_category" => "integer",
			"written_by" => "integer",
			"editor_by" => "integer",
			"written_date" => "date",
			"publish_date" => "date",
			"source" => "integer",
			"livereport" => "integer",
			"youtube" => "text_keyword",
			"related_id" => "text_keyword",
			"editor" => "text_keyword",
			"editor_fullname" => "text_keyword",
			"editor_id" => "integer",
			"hit" => "integer",
			"section" => "text_keyword",
			"writter" => "text_keyword",
			"writter_fullname" => "text_keyword",
			"writter_username" => "text_keyword",
			"writter_id" => "integer",
			"c_alias" => "text_keyword",
			"c_title" => "text_keyword",
			"s_title" => "text_keyword",
			"sstatus" => "integer",
			"name_source" => "text_keyword",
			"url_source" => "text_keyword",
			"quote_by" => "integer",
			"photo_written" => "text",
			"tagging" => "nested_tagging",
			"penulis_related" => "nested_penulis_related",
			"article_lokasi" => "nested_article_lokasi",
			"modified_date" => "date_null",
			"id_narasumber" => "integer",
			"type_narasumber" => "keyword",
			"value_narasumber" => "text_keyword",
			"title_narasumber" => "text_keyword",
			"url_narasumber" => "keyword",
			"description_narasumber" => "text",
			"image_narasumber" => "text",
			"sosmed_account_narasumber" => "text_keyword",
			"status_narasumber" => "integer",
			"allnetwork_id" => "long",
			"foto_cross_domain" => "integer",
			"id_konten_kreatif" => "integer",
			"pageviews" => "integer",
			"index_year" => "date_only_year"
		);
	$response = $opensearch->create($index,$tables);

	echo "<pre>";
	print_r($tables);
	print_r($response);
	echo "</pre>";

	unset($opensearch);
}	
?>