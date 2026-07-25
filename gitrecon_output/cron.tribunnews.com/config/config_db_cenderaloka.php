<?php
include_once "/var/www/html/web-cron/config/config.php";

//RDS
class config_db_cenderaloka{
    private $db_host_dev;
    private $db_username_dev;
    private $db_password_dev;
    private $db_host_prod;
    private $db_username_prod;
    private $db_password_prod;   

    public function __construct()
    {
        $this->db_host_dev = RDS_CENDERALOKA_HOST_DEV;
        $this->db_username_dev = RDS_CENDERALOKA_USERNAME_DEV;
        $this->db_password_dev = RDS_CENDERALOKA_PASSWORD_DEV;

        // $this->db_host_prod = RDS_TJB_HOST_MASTER_PROD;
        // $this->db_username_prod = RDS_TJB_USERNAME_MASTER_PROD;
        // $this->db_password_prod = RDS_TJB_PASSWORD_MASTER_PROD;
    }
    
    public function conn_to_db_cenderaloka_dev()
    {
        $db_name_dev = "cenderaloka";
        $mysqli = new mysqli($this->db_host_dev, $this->db_username_dev,$this->db_password_dev,$db_name_dev);
        if ($mysqli->connect_errno) {
            echo "Failed to connect to MySQL: " . $mysqli -> connect_error;
            exit();
        }

        return $mysqli;
    }

    // public function conn_to_db_cenderaloka_prod()
    // {
    //     $db_name_prod = "cenderaloka";
    //     $mysqli = new mysqli($this->db_host_prod, $this->db_username_prod,$this->db_password_prod,$db_name_prod);
    //     if ($mysqli->connect_errno) {
    //         echo "Failed to connect to MySQL: " . $mysqli -> connect_error;
    //         exit();
    //     }

    //     return $mysqli;
    // }



}


?>