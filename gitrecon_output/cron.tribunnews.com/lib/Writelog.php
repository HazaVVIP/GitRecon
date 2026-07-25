<?php

/*
How to use in controller

$this->load->library('Writelog');
$this->writelog->Log(PATH_ASSETS."/json/","xxx");
$this->writelog->doLogInfo("doLogInfo");
$this->writelog->doLogError("doLogError");
$this->writelog->closeLog();

*/

class Writelog{
	var $folder_location;
	var $filename;
	var $log_file;
	var $fhandle;
	var $resultarray;
	
	public function __construct(){
        //$CI =& get_instance();
    }
	
	public function Cache($folder, $filename, $arrvalue=array()){
		
		if(count($arrvalue) > 0){
			$this->folder_location = $folder;
			$this->filename = $filename;
			$this->log_file = $this->folder_location . $this->filename;
			$this->resultarray = json_encode($arrvalue);
			if (!$this->fhandle = fopen($this->log_file, 'w+')) {
				 die("Cannot open file $this->log_file");
			}
			if (fwrite($this->fhandle, $this->resultarray) === FALSE) {
				die("Cannot write to file $this->log_file");
			}
			
			fclose($this->fhandle);
		}	
		
	}
	
	public function Log($folder, $filename){
		$date = date("dmY",time());
		$arr_date = explode("-",$date);
		$this->folder_location = $folder;
		$this->filename = $filename. "-" . $date. ".txt";
		$this->log_file = $this->folder_location . $this->filename;
		$this->fhandle  = fopen($this->log_file,"a+");
	}

	public function doLogInfo($strLog){
		$logTime = date("Y-m-d H:i:s", time());

		fwrite($this->fhandle,"[" . $logTime . "] - INFO - ");
		fwrite($this->fhandle,$strLog."\r\n");
	}
	
	public function doLogError($strLog){
		$logTime = date("Y-m-d H:i:s", time());

		fwrite($this->fhandle,"[" . $logTime . "] - ERROR - ");
		fwrite($this->fhandle,$strLog."\r\n");
	}
	
	public function doLogDebug($strLog){
		$logTime = date("Y-m-d H:i:s", time());

		fwrite($this->fhandle,"[" . $logTime . "] - DEBUG - ");
		fwrite($this->fhandle,$strLog."\r\n");
	}
	
	public function closeLog(){
		fclose($this->fhandle) ;
	}
}
?>
