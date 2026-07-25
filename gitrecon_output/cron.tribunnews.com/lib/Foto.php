<?php 
include DOC_ROOT."config/config.php";
Class Foto
{
	private $s3;
	function __construct()
	{
		//$this->ci =& get_instance();
		//$this->ci->load->library('s3');
		$this->server = cdn_url.img_path;
		$this->imgpath = img_path;
		$this->s3 = new s3();
	}

	function cekfile($file)	
	{
		return $this->s3->getObjectInfo(bucket_s3,$file,FALSE);
	}
	
	function path($date) 
	{
		$path = strtotime($date);
		return date("Y/n/",$path); 
	}

	function get_thumb($id,$title,$date,$filename,$w='90',$h='60',$urut="1",$preview=TRUE) 
	{
		$file = $id."/".$urut."-".$filename."-thumb.jpg";
		return "<img src='".$this->server.$this->path($date).$file."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."' style='border-radius: 5px; margin-bottom: 0 !important;'/>";

	}
	
	function get_banner_url($filename,$preview=TRUE) 
	{
		$file = "banner/images/".$filename;
		return $this->server.$file;
	}
	
	function get_banner_thumbs_url($filename,$preview=TRUE) 
	{
		$file = "banner/thumbs/".$filename;
		return $this->server.$file;
	}
	
	function get_thumb_url_all($id,$date,$image_files,$preview=TRUE)
	{
		$arr = @unserialize($image_files);
		$arrImage = array();
		$urlImage = array();

		foreach($arr as $num => $item)
		{
			array_push($arrImage, $item['thumb']);
		}

		foreach($arrImage as $num => $item)
		{
			$file = $id."/".$item;

			if($this->cekfile($this->imgpath.$this->path($date).$file))
			{
				
				array_push($urlImage, $this->server.$this->path($date).$file);
			}
		}

		return $urlImage;
	}

	function get_image_url_all($id,$date,$image_files,$preview=TRUE)
	{
		$arr = unserialize($image_files);
		$arrImage = array();
		$urlImage = array();

		foreach($arr as $num => $item)
		{
			array_push($arrImage, $item['file']);
		}

		foreach($arrImage as $num => $item)
		{
			$file = $id."/".$item;

			if($this->cekfile($this->imgpath.$this->path($date).$file))
			{
				
				array_push($urlImage, $this->server.$this->path($date).$file);
			}
		}

		return $urlImage;
	}

	function get_thumb_url($id,$date,$filename,$urut="1",$preview=TRUE) 
	{
		$file = $id."/".$urut."-".$filename."-thumb.jpg";
		return $this->server.$this->path($date).$file;

	}

	function get_image_url($id,$date,$filename,$urut="1",$preview=TRUE) 
	{
		$file = $id."/".$urut."-".$filename.".jpg";
		if($this->cekfile($this->imgpath.$this->path($date).$file))
			return $this->server.$this->path($date).$file;
		else
			return false;
	}
	function get_image_url_view($id,$date,$filename,$urut=""){
	if(empty($urut)) $urut='1';
	$file= $id."/"."$urut-".$filename.".jpg";
		$url=$this->server.$this->path($date).$file;
	return $url;
	}
	function get_image($id,$title,$date,$filename,$w='500',$h='500') 
	{

		$file1 = $id."/"."1-".$filename.".jpg";
		$file2 = $id."/"."2-".$filename.".jpg";
		$file3 = $id."/"."3-".$filename.".jpg";
		$file4 = $id."/"."4-".$filename.".jpg";
		$file5 = $id."/"."5-".$filename.".jpg";
		$file6 = $id."/"."6-".$filename.".jpg";
		$file7 = $id."/"."7-".$filename.".jpg";
		$file8 = $id."/"."8-".$filename.".jpg";
		$file9 = $id."/"."9-".$filename.".jpg";
		$file10 = $id."/"."10-".$filename.".jpg";
		$no = 0;
		if($this->cekfile($this->imgpath.$this->path($date).$file1)):
			$img .= "<img src='".$this->server.$this->path($date).$file1."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/>";
			$slider_img .= '<li><a class="ns-img" href="'.$this->server.$this->path($date).$file1.'"></a></li>';
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file1."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file2)):
			$img .= "<img src='".$this->server.$this->path($date).$file2."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/>";
			$slider_img .= '<li><a class="ns-img" href="'.$this->server.$this->path($date).$file2.'"></a></li>';
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file2."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file3)):
			$img .= "<img src='".$this->server.$this->path($date).$file3."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/>";
			$slider_img .= '<li><a class="ns-img" href="'.$this->server.$this->path($date).$file3.'"></a></li>';
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file3."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file4)):
			$img .= "<img src='".$this->server.$this->path($date).$file4."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/>";
			$slider_img .= '<li><a class="ns-img" href="'.$this->server.$this->path($date).$file4.'"></a></li>';
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file4."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file5)):
			$img .= "<img src='".$this->server.$this->path($date).$file5."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/>";
			$slider_img .= '<li><a class="ns-img" href="'.$this->server.$this->path($date).$file5.'"></a></li>';
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file5."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file6)):
			$img .= "<img src='".$this->server.$this->path($date).$file6."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/>";
			$slider_img .= '<li><a class="ns-img" href="'.$this->server.$this->path($date).$file6.'"></a></li>';
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file6."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file7)):
			$img .= "<img src='".$this->server.$this->path($date).$file7."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/>";
			$slider_img .= '<li><a class="ns-img" href="'.$this->server.$this->path($date).$file7.'"></a></li>';
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file7."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file8)):
			$img .= "<img src='".$this->server.$this->path($date).$file8."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/>";
			$slider_img .= '<li><a class="ns-img" href="'.$this->server.$this->path($date).$file8.'"></a></li>';
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file8."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file9)):
			$img .= "<img src='".$this->server.$this->path($date).$file9."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/>";
			$slider_img .= '<li><a class="ns-img" href="'.$this->server.$this->path($date).$file9.'"></a></li>';
			// $slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file9."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file10)):
			$img .= "<img src='".$this->server.$this->path($date).$file10."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/>";
			$slider_img .= '<li><a class="ns-img" href="'.$this->server.$this->path($date).$file10.'"></a></li>';
			// $slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file10."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
			$no++;
		endif;
		if($img !== "") return array("img"=>$img,"slider_img"=>$slider_img,"slider_img_new" => $slider_img_new,"total"=>$no); else return false;
	}
	
	function get_image_new($id,$title,$date,$filename,$w='500',$h='500') {
		$file1 = $id."/"."1-".$filename.".jpg";
		$file2 = $id."/"."2-".$filename.".jpg";
		$file3 = $id."/"."3-".$filename.".jpg";
		$file4 = $id."/"."4-".$filename.".jpg";
		$file5 = $id."/"."5-".$filename.".jpg";
		$file6 = $id."/"."6-".$filename.".jpg";
		$file7 = $id."/"."7-".$filename.".jpg";
		$file8 = $id."/"."8-".$filename.".jpg";
		$file9 = $id."/"."9-".$filename.".jpg";
		$file10 = $id."/"."10-".$filename.".jpg";
		$no = 0;
		$img="";
		if($this->cekfile($this->imgpath.$this->path($date).$file1)):
			$img .= "<a href='".$this->server.$this->path($date).$file1."' class='glightbox'><img class='mySlides' src='".$this->server.$this->path($date).$file1."' style='width:100%' alt='".$title."'></a>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file2)):
			$img .= "<a href='".$this->server.$this->path($date).$file2."' class='glightbox'><img class='mySlides' src='".$this->server.$this->path($date).$file2."' style='width:100%' alt='".$title."'></a>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file3)):
			$img .= "<a href='".$this->server.$this->path($date).$file3."' class='glightbox'><img class='mySlides' src='".$this->server.$this->path($date).$file3."' style='width:100%' alt='".$title."'></a>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file4)):
			$img .= "<a href='".$this->server.$this->path($date).$file4."' class='glightbox'><img class='mySlides' src='".$this->server.$this->path($date).$file4."' style='width:100%' alt='".$title."'></a>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file5)):
			$img .= "<a href='".$this->server.$this->path($date).$file5."' class='glightbox'><img class='mySlides' src='".$this->server.$this->path($date).$file5."' style='width:100%' alt='".$title."'></a>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file6)):
			$img .= "<a href='".$this->server.$this->path($date).$file6."' class='glightbox'><img class='mySlides' src='".$this->server.$this->path($date).$file6."' style='width:100%' alt='".$title."'></a>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file7)):
			$img .= "<a href='".$this->server.$this->path($date).$file7."' class='glightbox'><img class='mySlides' src='".$this->server.$this->path($date).$file7."' style='width:100%' alt='".$title."'></a>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file8)):
			$img .= "<a href='".$this->server.$this->path($date).$file8."' class='glightbox'><img class='mySlides' src='".$this->server.$this->path($date).$file8."' style='width:100%' alt='".$title."'></a>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file9)):
			$img .= "<a href='".$this->server.$this->path($date).$file9."' class='glightbox'><img class='mySlides' src='".$this->server.$this->path($date).$file9."' style='width:100%' alt='".$title."'></a>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file10)):
			$img .= "<a href='".$this->server.$this->path($date).$file10."' class='glightbox'><img class='mySlides' src='".$this->server.$this->path($date).$file10."' style='width:100%' alt='".$title."'></a>";
			$no++;
		endif;
		if($img !== "") return array("img"=>$img,"total"=>$no); else return false;
	}

	function get_image_thumb($id,$title,$date,$filename,$w='60',$h='45') 
	{
		$file1 = $id."/"."1-".$filename."-thumb.jpg";
		$file2 = $id."/"."2-".$filename."-thumb.jpg";
		$file3 = $id."/"."3-".$filename."-thumb.jpg";
		$file4 = $id."/"."4-".$filename."-thumb.jpg";
		$file5 = $id."/"."5-".$filename."-thumb.jpg";
		$file6 = $id."/"."6-".$filename."-thumb.jpg";
		$file7 = $id."/"."7-".$filename."-thumb.jpg";
		$file8 = $id."/"."8-".$filename."-thumb.jpg";
		$file9 = $id."/"."9-".$filename."-thumb.jpg";
		$file10 = $id."/"."10-".$filename."-thumb.jpg";
		$img = "";
		if($this->cekfile($this->imgpath.$this->path($date).$file1)):
			$img .= "<img src='".$this->server.$this->path($date).$file1."' height='".$h."' width='".$w."' border='0' align='center' style='margin-right:2px;' alt='".$title."'/>";
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file1."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file2)):
			$img .= "<img src='".$this->server.$this->path($date).$file2."' height='".$h."' width='".$w."' border='0' align='center' style='margin-right:2px;' alt='".$title."'/>";
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file2."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file3)):
			$img .= "<img src='".$this->server.$this->path($date).$file3."' height='".$h."' width='".$w."' border='0' align='center' style='margin-right:2px;' alt='".$title."'/>";
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file3."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file4)):
			$img .= "<img src='".$this->server.$this->path($date).$file4."' height='".$h."' width='".$w."' border='0' align='center' style='margin-right:2px;' alt='".$title."'/>";
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file4."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file5)):
			$img .= "<img src='".$this->server.$this->path($date).$file5."' height='".$h."' width='".$w."' border='0' align='center' style='margin-right:2px;' alt='".$title."'/>";
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file5."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file6)):
			$img .= "<img src='".$this->server.$this->path($date).$file6."' height='".$h."' width='".$w."' border='0' align='center' style='margin-right:2px;' alt='".$title."'/>";
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file6."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file7)):
			$img .= "<img src='".$this->server.$this->path($date).$file7."' height='".$h."' width='".$w."' border='0' align='center' style='margin-right:2px;' alt='".$title."'/>";
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file7."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file8)):
			$img .= "<img src='".$this->server.$this->path($date).$file8."' height='".$h."' width='".$w."' border='0' align='center' style='margin-right:2px;' alt='".$title."'/>";
			$slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file8."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file9)):
			$img .= "<img src='".$this->server.$this->path($date).$file9."' height='".$h."' width='".$w."' border='0' align='center' style='margin-right:2px;' alt='".$title."'/>";
			// $slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file9."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file10)):
			$img .= "<img src='".$this->server.$this->path($date).$file10."' height='".$h."' width='".$w."' border='0' align='center' style='margin-right:2px;' alt='".$title."'/>";
			// $slider_img_new .= "<li><img src='".$this->server.$this->path($date).$file10."' height='".$h."' width='".$w."' border='0' align='left' alt='".$title."'/></li>";
		endif;
		if($img !== "") return array("img"=>$img,"slider_img_new" => $slider_img_new); else return false;
	}

	function get_image_thumb_mobile($id,$title,$date,$filename,$w='120',$h='90') 
	{
		$file1 = $id."/"."1-".$filename.".jpg";
		$file2 = $id."/"."2-".$filename.".jpg";
		$file3 = $id."/"."3-".$filename.".jpg";
		$img = "";
		if($this->cekfile($this->imgpath.$this->path($date).$file1)):
			$img .= "<img src='".$this->server.$this->path($date).$file1."' alt='".$title."'/>";
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file2)):
			$img .= "<img src='".$this->server.$this->path($date).$file2."' alt='".$title."'/>";
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file3)):
			$img .= "<img src='".$this->server.$this->path($date).$file3."' alt='".$title."'/>";
		endif;
		if($img !== "") return $img; else return false;
	}
	
	function get_image_template_new($id,$title,$date,$filename,$w='500',$h='500') {
		$file1 = $id."/"."1-".$filename.".jpg";
		$file2 = $id."/"."2-".$filename.".jpg";
		$file3 = $id."/"."3-".$filename.".jpg";
		$file4 = $id."/"."4-".$filename.".jpg";
		$file5 = $id."/"."5-".$filename.".jpg";
		$file6 = $id."/"."6-".$filename.".jpg";
		$file7 = $id."/"."7-".$filename.".jpg";
		$file8 = $id."/"."8-".$filename.".jpg";
		$file9 = $id."/"."9-".$filename.".jpg";
		$file10 = $id."/"."10-".$filename.".jpg";
		//thumbnails
		$file1_thumb = $id."/"."1-".$filename."-thumb.jpg";
		$file2_thumb = $id."/"."2-".$filename."-thumb.jpg";
		$file3_thumb = $id."/"."3-".$filename."-thumb.jpg";
		$file4_thumb = $id."/"."4-".$filename."-thumb.jpg";
		$file5_thumb = $id."/"."5-".$filename."-thumb.jpg";
		$file6_thumb = $id."/"."6-".$filename."-thumb.jpg";
		$file7_thumb = $id."/"."7-".$filename."-thumb.jpg";
		$file8_thumb = $id."/"."8-".$filename."-thumb.jpg";
		$file9_thumb = $id."/"."9-".$filename."-thumb.jpg";
		$file10_thumb = $id."/"."10-".$filename."-thumb.jpg";
		$no = 0;
		$img = "";
		if($this->cekfile($this->imgpath.$this->path($date).$file1)):
			$img .= '<div class="swiper-slide">
						<div class="thumb-image">
						<a href="'.$this->server.$this->path($date).$file1.'" class="glightbox"> 
							<img src="'.$this->server.$this->path($date).$file1.'" class="img-responsive" alt="'.$title.'">
						</a> 
						</div>
					</div>';
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file2)):
			$img .= '<div class="swiper-slide">
						<div class="thumb-image">
						<a href="'.$this->server.$this->path($date).$file2.'" class="glightbox"> 
							<img src="'.$this->server.$this->path($date).$file2.'" class="img-responsive" alt="'.$title.'"> 
						</div>
						</a> 
					</div>';
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file3)):
			$img .= '<div class="swiper-slide">
						<div class="thumb-image">
						<a href="'.$this->server.$this->path($date).$file3.'" class="glightbox"> 
							<img src="'.$this->server.$this->path($date).$file3.'" class="img-responsive" alt="'.$title.'"> 
						</div>
						</a> 
					</div>';
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file4)):
			$img .= '<div class="swiper-slide">
						<div class="thumb-image">
						<a href="'.$this->server.$this->path($date).$file4.'" class="glightbox"> 
							<img src="'.$this->server.$this->path($date).$file4.'" class="img-responsive" alt="'.$title.'"> 
						</div>
						</a> 
					</div>';
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file5)):
			$img .= '<div class="swiper-slide">
						<div class="thumb-image">
						<a href="'.$this->server.$this->path($date).$file5.'" class="glightbox"> 
							<img src="'.$this->server.$this->path($date).$file5.'" class="img-responsive" alt="'.$title.'"> 
						</div>
						</a> 
					</div>';
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file6)):
			$img .= '<div class="swiper-slide">
						<div class="thumb-image">
						<a href="'.$this->server.$this->path($date).$file6.'" class="glightbox"> 
							<img src="'.$this->server.$this->path($date).$file6.'" class="img-responsive" alt="'.$title.'"> 
						</div>
						</a> 
					</div>';
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file7)):
			$img .= '<div class="swiper-slide">
						<div class="thumb-image">
						<a href="'.$this->server.$this->path($date).$file7.'" class="glightbox"> 
							<img src="'.$this->server.$this->path($date).$file7.'" class="img-responsive" alt="'.$title.'"> 
						</div>
						</a> 
					</div>';
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file8)):
			$img .= '<div class="swiper-slide">
						<div class="thumb-image">
						<a href="'.$this->server.$this->path($date).$file8.'" class="glightbox"> 
							<img src="'.$this->server.$this->path($date).$file8.'" class="img-responsive" alt="'.$title.'"> 
						</div>
						</a> 
					</div>';
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file9)):
			$img .= '<div class="swiper-slide">
						<div class="thumb-image">
						<a href="'.$this->server.$this->path($date).$file9.'" class="glightbox"> 
							<img src="'.$this->server.$this->path($date).$file9.'" class="img-responsive" alt="'.$title.'"> 
						</div>
						</a> 
					</div>';
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file10)):
			$img .= '<div class="swiper-slide">
						<div class="thumb-image">
						<a href="'.$this->server.$this->path($date).$file10.'" class="glightbox"> 
							<img src="'.$this->server.$this->path($date).$file10.'" class="img-responsive" alt="'.$title.'"> 
						</div>
						</a> 
					</div>';
			$no++;
		endif;
		if($img !== "") return array("img"=>$img,"total"=>$no); else return false;
	}

	//Baru 2017
	function get_image_template_terkait($id,$title,$date,$filename,$w='400',$h='400') 
	{
		$file1_thumb = $id."/"."1-".$filename."-thumb.jpg";
		$file2_thumb = $id."/"."2-".$filename."-thumb.jpg";
		$file3_thumb = $id."/"."3-".$filename."-thumb.jpg";
		$file4_thumb = $id."/"."4-".$filename."-thumb.jpg";
		$file5_thumb = $id."/"."5-".$filename."-thumb.jpg";
		$file6_thumb = $id."/"."6-".$filename."-thumb.jpg";
		$file7_thumb = $id."/"."7-".$filename."-thumb.jpg";
		$file8_thumb = $id."/"."8-".$filename."-thumb.jpg";
		$file9_thumb = $id."/"."9-".$filename."-thumb.jpg";
		$file10_thumb = $id."/"."10-".$filename."-thumb.jpg";
		$no = 0;

		if($this->cekfile($this->imgpath.$this->path($date).$file1_thumb)):
			$img .= '
					<img data-src="'.$this->server.$this->path($date).$file1_thumb.'" class="img-responsive lazyload" alt="'.$title.'"> 
			';
			$no++;
		endif;
		if($img !== "") return array("img"=>$img,"total"=>$no); else return false;
	}

	function get_image_new_slide($id,$title,$date,$filename,$w='500',$h='500') 
	{

		$file1 = $id."/"."1-".$filename.".jpg";
		$file2 = $id."/"."2-".$filename.".jpg";
		$file3 = $id."/"."3-".$filename.".jpg";
		$file4 = $id."/"."4-".$filename.".jpg";
		$file5 = $id."/"."5-".$filename.".jpg";
		$file6 = $id."/"."6-".$filename.".jpg";
		$file7 = $id."/"."7-".$filename.".jpg";
		$file8 = $id."/"."8-".$filename.".jpg";
		$file9 = $id."/"."9-".$filename.".jpg";
		$file10 = $id."/"."10-".$filename.".jpg";
		$no = 0;
		$img = "";
		if($this->cekfile($this->imgpath.$this->path($date).$file1)):
			$img .= "<div class='w3-col s4'><img class='demo w3-opacity w3-hover-opacity-off w3-red' src='".$this->server.$this->path($date).$file1."' style='width:100%;cursor:pointer' alt='".$title."' onclick='currentDiv(1)'></div>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file2)):
			$img .= "<div class='w3-col s4'><img class='demo w3-opacity w3-hover-opacity-off' src='".$this->server.$this->path($date).$file2."' style='width:100%;cursor:pointer' alt='".$title."' onclick='currentDiv(2)'></div>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file3)):
			$img .= "<div class='w3-col s4'><img class='demo w3-opacity w3-hover-opacity-off' src='".$this->server.$this->path($date).$file3."' style='width:100%;cursor:pointer' alt='".$title."' onclick='currentDiv(3)'></div>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file4)):
			$img .= "<div class='w3-col s4'><img class='demo w3-opacity w3-hover-opacity-off' src='".$this->server.$this->path($date).$file4."' style='width:100%;cursor:pointer' alt='".$title."' onclick='currentDiv(4)'></div>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file5)):
			$img .= "<div class='w3-col s4'><img class='demo w3-opacity w3-hover-opacity-off' src='".$this->server.$this->path($date).$file5."' style='width:100%;cursor:pointer' alt='".$title."' onclick='currentDiv(5)'></div>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file6)):
			$img .= "<div class='w3-col s4'><img class='demo w3-opacity w3-hover-opacity-off' src='".$this->server.$this->path($date).$file6."' style='width:100%;cursor:pointer' alt='".$title."' onclick='currentDiv(6)'></div>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file7)):
			$img .= "<div class='w3-col s4'><img class='demo w3-opacity w3-hover-opacity-off' src='".$this->server.$this->path($date).$file7."' style='width:100%;cursor:pointer' alt='".$title."' onclick='currentDiv(7)'></div>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file8)):
			$img .= "<div class='w3-col s4'><img class='demo w3-opacity w3-hover-opacity-off' src='".$this->server.$this->path($date).$file8."' style='width:100%;cursor:pointer' alt='".$title."' onclick='currentDiv(8)'></div>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file9)):
			$img .= "<div class='w3-col s4'><img class='demo w3-opacity w3-hover-opacity-off' src='".$this->server.$this->path($date).$file9."' style='width:100%;cursor:pointer' alt='".$title."' onclick='currentDiv(9)'></div>";
			$no++;
		endif;
		if($this->cekfile($this->imgpath.$this->path($date).$file10)):
			$img .= "<div class='w3-col s4'><img class='demo w3-opacity w3-hover-opacity-off' src='".$this->server.$this->path($date).$file10."' style='width:100%;cursor:pointer' alt='".$title."' onclick='currentDiv(10)'></div>";
			$no++;
		endif;
		if($img !== "") return array("img"=>$img,"total"=>$no); else return false;
	}


}




