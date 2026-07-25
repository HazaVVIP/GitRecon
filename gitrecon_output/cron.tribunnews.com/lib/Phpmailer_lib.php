<?php 

require 'phpmailer/class.phpmailer.php';
include_once PATH_ROOT."config/config.php";

class Phpmailer_lib {
	
	public function __construct()
	{
		//$this->CI = & get_instance();
	}
	
	public function send_smtp($to, $subject, $message, $fromname, $pathfile = null){
		$respond['status'] = 1;
		$respond['err'] = "";
		
		$mail = new PHPMailer();
		$mail->IsSMTP();  
		$mail->Host     = "smtp.gmail.com"; 
		$mail->Port		= 465;
		$mail->SMTPAuth = true;
		$mail->SMTPSecure = 'ssl';
		$mail->Username = SMTP_USERNAME;
		$mail->Password = SMTP_PASSWORD;
		$mail->From     = SMTP_FROM;
		$mail->FromName = $fromname;
		
		$mail->AddAddress($to);
		$mail->IsHTML(true);
		$mail->Subject  = $subject;
		$mail->Body		= $message;
		if(!empty($pathfile)){
			$mail->AddAttachment($pathfile);   
		}
		if(!$mail->Send()) {
		  $respond['status'] = 0;
		  $respond['err'] = $mail->ErrorInfo;
		} 
		
		unset($mail);
		
		return $respond;
	}
}

?>
