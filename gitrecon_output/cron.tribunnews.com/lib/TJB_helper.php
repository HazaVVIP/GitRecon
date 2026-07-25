<?php
include_once PATH_TJB_MODEL."model_settlement.php";

class TJB_Helper {

    private $model_settlement;

    function __construct() {
        //get conn db
        $this->conn_db = new config_db();
        $this->model_settlement = new model_settlement();
    }
    public function handle_settlement_tjb_status($invoice,$tjb_status=0){

		$rsQuery = $this->model_settlement->get_by_invoice_commerce($invoice);
        $rsSettlement =  mysqli_fetch_assoc($rsQuery);

		$comSettlementId = isset($rsSettlement['com_settlement_id'])?$rsSettlement['com_settlement_id']:0;
		$rsTotalQuerySettlementStatus = $this->model_settlement->get_total_settlement_commerce_status($invoice,$tjb_status);
		$rsTotalSettlementStatus =  mysqli_fetch_assoc($rsTotalQuerySettlementStatus);
        $totalTotalSettlementStatus = isset($rsTotalSettlementStatus['total'])?$rsTotalSettlementStatus['total']:0;
		
		$comSettlementStatusId = 0;
		if($totalTotalSettlementStatus < 1){
			$dataComSettlementStatus = array(
					   'com_settlement_status_created' => date('Y-m-d H:i:s'),
					   'com_settlement_id' => $comSettlementId,
					   'invoice' => $invoice,
					   'tjb_status' => $tjb_status
					);
			$comSettlementStatusId = $this->model_settlement->insert_com_settlement_status($dataComSettlementStatus); 
		}
		
		return $comSettlementStatusId;
	}
}

?>