<?php
include_once "/var/www/html/web-cron/config/config.php";

//RDS
class config_db_booking{
    private $db_host_prod;
    private $db_username_prod;
    private $db_password_prod;
    private $db_host_dev;
    private $db_username_dev;
    private $db_password_dev;

    public function __construct()
    {
        $this->db_host_prod     = BOOKING_HOST_PROD;//BOOKING_HOST_PROD;
        $this->db_username_prod = BOOKING_USERNAME_PROD;//BOOKING_USERNAME_PROD;
        $this->db_password_prod = BOOKING_PASSWORD_PROD;//BOOKING_PASSWORD_PROD;

        $this->db_host_dev     = BOOKING_HOST_DEV;//BOOKING_HOST_DEV;
        $this->db_username_dev = BOOKING_USERNAME_DEV;//BOOKING_USERNAME_DEV;
        $this->db_password_dev = BOOKING_PASSWORD_DEV;//BOOKING_PASSWORD_DEV;
		
		$this->db_host_prod_read     = BOOKING_READ_HOST_PROD;//BOOKING_HOST_PROD;
        $this->db_username_prod_read = BOOKING_READ_USERNAME_PROD;//BOOKING_USERNAME_PROD;
        $this->db_password_prod_read = BOOKING_READ_PASSWORD_PROD;//BOOKING_PASSWORD_PROD;
		
		
    }
    
    public function conn_to_db_prod()
    {
        $db_name = "booking";
        $mysqli = new mysqli($this->db_host_prod, $this->db_username_prod, $this->db_password_prod, $db_name);
        if ($mysqli->connect_errno) {
            echo "Failed to connect to MySQL: " . $mysqli -> connect_error;
            exit();
        }

        return $mysqli;
    }    
	
	public function conn_to_db_prod_read()
    {
        $db_name = "booking";
        $mysqli = new mysqli($this->db_host_prod_read, $this->db_username_prod_read, $this->db_password_prod_read, $db_name);
        if ($mysqli->connect_errno) {
            echo "Failed to connect to MySQL: " . $mysqli -> connect_error;
            exit();
        }

        return $mysqli;
    }    


    public function conn_to_db_dev()
    {
        $db_name = "booking";
        $mysqli = new mysqli($this->db_host_dev, $this->db_username_dev, $this->db_password_dev, $db_name);
        if ($mysqli->connect_errno) {
            echo "Failed to connect to MySQL: " . $mysqli -> connect_error;
            exit();
        }

        return $mysqli;
    }


}


?>