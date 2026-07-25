<?php if (!defined('BASEPATH')) exit('No direct script access allowed');
Class Query_method
{
	function __construct()
	{
		//$this->ci =& get_instance();
		$this->ci->load->driver('cache');
		$this->ci->load->library('memcached_library');
		// $this->ci->load->library('memcached_new_aws');
		$this->ci->load->database();
		$this->memcached = true;
	}

	function get($method,$model,$function,$type,$par,$key,$timeout,$par_to_key,$vback="") {
		if($this->memcached and $method == "memcached") :
			// echo "memcached run";
			$timeout = (int)$timeout;
			if($par_to_key == TRUE) $key = $key.(implode("+", $par));
			$cache_data = $this->ci->memcached_library->get($key);

			//if memcached lost data
			/* if(isset($par[0])){
				if($par[0]=="properti"){
					$cache_data = false;
				}
			} */

			if ($cache_data) :
				// echo "<p>memcamet: ".$key."</p>";
				$data = $cache_data;
			else :
				// echo "querymet".$key."<br/>";
				$this->ci->load->model($model);
				$query = @$this->ci->$model->$function($par[0],$par[1],$par[2],$par[3],$par[4],$par[5],$par[6],$par[7],$par[8],$par[9],$par[10],$par[11],$par[12],$par[13],$par[14],$par[15]);
				if ($query and $query->num_rows() > 0) :
					$data = $query->$type();
					$query->free_result();
				elseif($vback):
					$data = $vback;
				else :
					$data = "noexist";
					$timeout = 600;
				endif;
				$this->ci->memcached_library->set($key, $data, $timeout);

			endif;
		elseif($method == "file") :
			if($par_to_key == TRUE) $key = $key.(implode("+", $par));
			$cache_data = $this->ci->cache->file->get($key);
			if ($cache_data) :
				//echo "file cache";
				$data = $cache_data;
			else :
				//echo "query";
				$this->ci->load->model($model);
				$query = @$this->ci->$model->$function($par[0],$par[1],$par[2],$par[3],$par[4],$par[5],$par[6],$par[7],$par[8],$par[9],$par[10],$par[11],$par[12],$par[13],$par[14],$par[15]);
				if ($query) :
					$data = $query->$type();
					$this->ci->cache->file->save($key, $data, $timeout);
					$query->free_result();
				endif;
			endif;
		else:
			$this->ci->load->model($model);
			$query = @$this->ci->$model->$function($par[0],$par[1],$par[2],$par[3],$par[4],$par[5],$par[6],$par[7],$par[8],$par[9],$par[10],$par[11],$par[12],$par[13],$par[14],$par[15]);
			if ($query) :
				$data = $query->$type();
				$query->free_result();
			endif;
		endif;
		return $data;
	}

	function get_memcached($key) {
		if($this->memcached) :
			$cache_data = $this->ci->memcached_library->get($key);
			if($cache_data) return $cache_data; else return false;
		else : return false;
		endif;
	}

	function save_memcached($key,$data,$timeout) {
		if($this->memcached) :
			$timeout = (int)$timeout;
			$cache_data = $this->ci->memcached_library->set($key,$data,$timeout);
		endif;
	}

	function delete_memcached($key) {
		if($this->memcached) :
			$cache_data = $this->ci->memcached_library->delete($key);
			$status = "success delete ".$key;
			if($cache_data) return $status; else return false;
		else : return false;
		endif;
	}

	function get_file_cached($key) {
		$cache_data = $this->ci->cache->file->get($key);
		if($cache_data) return $cache_data; else return false;

	}

	function save_file_cached($key,$data,$timeout) {
		$cache_data = $this->ci->cache->file->save($key,$data,$timeout);
	}

	function check_connection(){
		return $this->ci->memcached_library->getstats();
	}

	function getTimeout($type = 'short'){
		if ($type == 'short'){
			return rand(1200,3000);
		}else{
			return rand(10000,50000);
		}
	}
}
