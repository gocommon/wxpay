package wxpay

const (
	kRefund        = "/secapi/pay/refund"
	kRefundSandbox = "/pay/refund"
)

// Refund https://pay.weixin.qq.com/wiki/doc/api/app/app.php?chapter=9_4&index=6
func (p *Client) Refund(param RefundParam) (result *RefundRsp, err error) {
	var api = kRefundSandbox
	if p.isProduction {
		api = kRefund
	}
	if err = p.doRequestWithTLS("POST", p.BuildAPI(api), param, &result); err != nil {
		return nil, err
	}
	return result, err
}
