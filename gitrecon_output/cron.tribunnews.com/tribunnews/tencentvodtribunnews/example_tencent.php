<?php


require_once 'TCloudAutoLoader.php';
// Import the client of the corresponding product module
use TencentCloud\Cvm\V20170312\CvmClient;
// Import the `Request` class corresponding to the request API
use TencentCloud\Cvm\V20170312\Models\DescribeInstancesRequest;
use TencentCloud\Common\Exception\TencentCloudSDKException;
use TencentCloud\Common\Credential;


class Example_tencent extends CI_Controller {

	function __construct()
       {
            parent::__construct();
			$this->load->helper('url');
			$this->load->library('pagination');
			$this->load->helper('text'); 
			$this->load->helper('date');
			$this->load->helper('string');
			$this->load->helper('date_tribun_helper');
			$this->load->helper('clear_strings');
			$this->load->driver('cache');
			
       }


	function index()
	{	
		
        try {
            // Instantiate a certificate object. The Tencent Cloud account `secretId` and `secretKey` need to be passed in as input parameters
            // $cred = new Credential("secretId", "secretKey");
            $cred = new Credential("IKIDX2siU6xmPsBG8oGZxy5JXp9aAe6VnDkU", "UxKiEmANeuHZjwEbxPj5RxiYQLAjP5vs"); // Tribun

            // # Instantiate the client object of the requested product (with CVM as an example)
            $client = new CvmClient($cred, "ap-guangzhou");

            // Instantiate a request object
            $req = new DescribeInstancesRequest();

            // Call the API you want to access through the client object. You need to pass in the request object
            $resp = $client->DescribeInstances($req);

            print_r($resp->toJsonString());
        }
        catch(TencentCloudSDKException $e) {
            echo $e;
        }
	}


}


?>