package wxpay

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	kUnifiedOrder = "/pay/unifiedorder"
	kOrderQuery   = "/pay/orderquery"
	kCloseOrder   = "/pay/closeorder"
	kDownloadBill = "/pay/downloadbill"
)

// UnifiedOrder https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=9_1
func (p *Client) UnifiedOrder(param UnifiedOrderParam) (result *UnifiedOrderRsp, err error) {
	if err = p.doRequest("POST", p.BuildAPI(kUnifiedOrder), param, &result); err != nil {
		return nil, err
	}
	return result, err
}

// AppPay APP 支付  https://pay.weixin.qq.com/wiki/doc/api/app/app.php?chapter=9_12&index=2#
func (p *Client) AppPay(param UnifiedOrderParam) (rsp *UnifiedOrderRsp, err error) {
	param.TradeType = K_TRADE_TYPE_APP
	rsp, err = p.UnifiedOrder(param)
	if err != nil {
		return nil, err
	}

	if rsp != nil {

		var u = url.Values{}
		u.Set("appid", param.AppID)
		u.Set("noncestr", GetNonceStr())
		u.Set("partnerid", p.mchID)
		u.Set("prepayid", rsp.PrepayID)
		u.Set("package", "Sign=WXPay")
		u.Set("timestamp", fmt.Sprintf("%d", time.Now().Unix()))
		u.Set("sign", SignMD5(u, p.apiKey))
		rsp.Payinfo = u.Encode()

	}
	return rsp, err
}

// JSAPIPay 微信内H5调起支付-公众号支付 https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=7_7&index=6
func (p *Client) JSAPIPay(param UnifiedOrderParam) (rsp *UnifiedOrderRsp, err error) {
	param.TradeType = K_TRADE_TYPE_JSAPI
	rsp, err = p.UnifiedOrder(param)
	if err != nil {
		return nil, err
	}

	if rsp != nil {

		var u = url.Values{}
		u.Set("appId", param.AppID)
		u.Set("nonceStr", GetNonceStr())
		u.Set("package", fmt.Sprintf("prepay_id=%s", rsp.PrepayID))
		u.Set("signType", kSignTypeMD5)
		u.Set("timeStamp", fmt.Sprintf("%d", time.Now().Unix()))
		u.Set("paySign", SignMD5(u, p.apiKey))

		rsp.Payinfo = u.Encode()

	}
	return rsp, err
}

// MiniAppPay 小程序支付 https://pay.weixin.qq.com/wiki/doc/api/wxa/wxa_api.php?chapter=7_7&index=5
func (p *Client) MiniAppPay(param UnifiedOrderParam) (rsp *UnifiedOrderRsp, err error) {
	return p.JSAPIPay(param)
}

// WebPay H5 支付 https://pay.weixin.qq.com/wiki/doc/api/H5.php?chapter=9_20&index=1
func (p *Client) WebPay(param UnifiedOrderParam) (rsp *UnifiedOrderRsp, err error) {
	param.TradeType = K_TRADE_TYPE_MWEB
	rsp, err = p.UnifiedOrder(param)
	if err != nil {
		return nil, err
	}

	if rsp != nil {

		rsp.Payinfo = rsp.MWebURL
	}
	return rsp, err
}

// NativePay NATIVE 扫码支付 https://pay.weixin.qq.com/wiki/doc/api/native.php?chapter=9_1
func (p *Client) NativePay(param UnifiedOrderParam) (rsp *UnifiedOrderRsp, err error) {
	param.TradeType = K_TRADE_TYPE_NATIVE
	rsp, err = p.UnifiedOrder(param)
	if err != nil {
		return nil, err
	}

	if rsp != nil {
		rsp.Payinfo = rsp.CodeURL
	}
	return rsp, err
}

// OrderQuery https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=9_2
func (p *Client) OrderQuery(param OrderQueryParam) (result *OrderQueryRsp, err error) {
	if err = p.doRequest("POST", p.BuildAPI(kOrderQuery), param, &result); err != nil {
		return nil, err
	}
	return result, err
}

// CloseOrder https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=9_3
func (p *Client) CloseOrder(param CloseOrderParam) (result *CloseOrderRsp, err error) {
	if err = p.doRequest("POST", p.BuildAPI(kCloseOrder), param, &result); err != nil {
		return nil, err
	}
	return result, err
}

var (
	XMLFlag = []byte("<xml>")
)

// DownloadBill https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=9_6
func (p *Client) DownloadBill(param DownloadBillParam) (result *DownloadBillRsp, err error) {
	key, err := p.getKey()
	if err != nil {
		return nil, err
	}

	vals, err := p.URLValues(param, key)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", p.BuildAPI(kDownloadBill), strings.NewReader(URLValueToXML(vals)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/xml")
	req.Header.Set("Content-Type", "application/xml;charset=utf-8")

	resp, err := p.Client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if bytes.Index(data, XMLFlag) == 0 {
		err = xml.Unmarshal(data, &result)
	} else {
		if p.isProduction {
			var r = bytes.NewReader(data)
			gr, err := gzip.NewReader(r)
			if err != nil {
				return nil, err
			}
			defer gr.Close()

			if data, err = ioutil.ReadAll(gr); err != nil {
				return nil, err
			}
		}

		result = &DownloadBillRsp{}
		result.ReturnCode = K_RETURN_CODE_SUCCESS
		result.ReturnMsg = "ok"
		result.Data = data
	}

	return result, err
}
