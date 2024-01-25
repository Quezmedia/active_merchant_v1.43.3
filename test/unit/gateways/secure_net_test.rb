require 'test_helper'

class SecureNetTest < Test::Unit::TestCase
  include CommStub

  def setup
    @gateway = SecureNetGateway.new(
      login: 'X',
      password: 'Y'
    )

    @credit_card = credit_card
    @amount = 100

    @options = {
      order_id: '1',
      billing_address: address,
      description: 'Store Purchase'
    }
  end

  def test_successful_authorization
    @gateway.expects(:ssl_post).returns(successful_authorization_response)

    assert response = @gateway.authorize(@amount, @credit_card, @options)
    assert_instance_of Response, response
    assert_success response

    assert_equal '12532160|1.00|2224', response.authorization
    assert response.test?
  end

  def test_failed_authorization
    @gateway.expects(:ssl_post).returns(failed_authorization_response)

    assert response = @gateway.authorize(@amount, @credit_card, @options)
    assert_instance_of Response, response
    assert_failure response

    assert_equal '12532160|1.00|2224', response.authorization
    assert response.test?
  end

  def test_successful_purchase
    @gateway.expects(:ssl_post).returns(successful_purchase_response)

    assert response = @gateway.purchase(@amount, @credit_card, @options)
    assert_instance_of Response, response
    assert_success response

    assert_equal '12533097|1.00|2224', response.authorization
    assert response.test?
  end

  def test_failed_purchase
    @gateway.expects(:ssl_post).returns(failed_purchase_response)

    assert response = @gateway.purchase(@amount, @credit_card, @options)
    assert_instance_of Response, response
    assert_failure response

    assert_equal '12533097|1.00|2224', response.authorization
    assert response.test?
  end

  def test_successful_capture
    @gateway.expects(:ssl_post).returns(successful_capture_response)

    assert response = @gateway.capture(@amount, '12533132', @options)
    assert_instance_of Response, response
    assert_success response

    assert_equal '12533132|1.00|2224', response.authorization
    assert response.test?
  end

  def test_failed_capture
    @gateway.expects(:ssl_post).returns(failed_capture_response)

    assert response = @gateway.capture(@amount, '12533132', @options)
    assert_instance_of Response, response
    assert_failure response

    assert_equal '12533132|1.00|2224', response.authorization
    assert response.test?
  end

  def test_successful_void
    @gateway.expects(:ssl_post).returns(successful_void_response)
    assert response = @gateway.void('12533174', @options)
    assert_success response
    assert_equal 'Approved', response.message
  end

  def test_failed_void
    @gateway.expects(:ssl_post).returns(failed_void_response)

    assert response = @gateway.void('123456', @options)
    assert_failure response
    assert_equal 'TRANSACTION ID DOES NOT EXIST FOR VOID', response.message
  end

  def test_successful_refund
    @gateway.expects(:ssl_post).returns(successful_refund_response)
    assert response = @gateway.refund(@amount, '123456789', @options)
    assert_success response
    assert_equal 'Approved', response.message
  end

  def test_failed_refund
    @gateway.expects(:ssl_post).returns(failed_refund_response)
    assert response = @gateway.refund(@amount, '12533185', @options)
    assert_failure response
    assert_equal 'CREDIT CANNOT BE COMPLETED ON AN UNSETTLED TRANSACTION', response.message
  end

  def test_order_id_is_truncated
    order_id = "SecureNet doesn't like order_ids greater than 25 characters."
    stub_comms do
      @gateway.purchase(@amount, @credit_card, order_id: order_id)
    end.check_request do |_endpoint, data, _headers|
      assert_match(/ORDERID>SecureNet doesn't like or</, data)
    end.respond_with(successful_purchase_response)
  end

  def test_failure_without_response_reason_text
    assert_nothing_raised do
      assert_equal '', @gateway.send(:message_from, {})
    end
  end

  def test_passes_optional_fields
    options = { description: 'Good Stuff', invoice_description: 'Sweet Invoice', invoice_number: '48' }
    stub_comms do
      @gateway.purchase(@amount, @credit_card, options)
    end.check_request do |_endpoint, data, _headers|
      assert_match(%r{NOTE>Good Stuff<}, data)
      assert_match(%r{INVOICEDESC>Sweet Invoice<}, data)
      assert_match(%r{INVOICENUM>48<}, data)
    end.respond_with(successful_purchase_response)
  end

  def test_only_passes_optional_fields_if_specified
    stub_comms do
      @gateway.purchase(@amount, @credit_card, {})
    end.check_request do |_endpoint, data, _headers|
      assert_no_match(%r{NOTE}, data)
      assert_no_match(%r{INVOICEDESC}, data)
      assert_no_match(%r{INVOICENUM}, data)
    end.respond_with(successful_purchase_response)
  end

  def test_passes_with_no_developer_id
    stub_comms do
      @gateway.purchase(@amount, @credit_card, {})
    end.check_request do |_endpoint, data, _headers|
      assert_no_match(%r{DEVELOPERID}, data)
    end.respond_with(successful_purchase_response)
  end

  def test_passes_with_developer_id
    stub_comms do
      @gateway.purchase(@amount, @credit_card, developer_id: '1234')
    end.check_request do |_endpoint, data, _headers|
      assert_match(%r{DEVELOPERID}, data)
    end.respond_with(successful_purchase_response)
  end

  def test_passes_with_test_mode
    stub_comms do
      @gateway.purchase(@amount, @credit_card, test_mode: false)
    end.check_request do |_endpoint, data, _headers|
      assert_match(%r{<TEST>FALSE</TEST>}, data)
    end.respond_with(successful_purchase_response)
  end

  def test_passes_without_test_mode
    stub_comms do
      @gateway.purchase(@amount, @credit_card)
    end.check_request do |_endpoint, data, _headers|
      assert_match(%r{<TEST>TRUE</TEST>}, data)
    end.respond_with(successful_purchase_response)
  end

  def test_scrub
    assert @gateway.supports_scrubbing?
    assert_equal @gateway.scrub(pre_scrubbed), post_scrubbed
  end

  private

  # Place raw successful response from gateway here
  def successful_authorization_response
    '<GATEWAYRESPONSE xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><ASPREPONSE i:nil="true"/><TRANSACTIONRESPONSE><RESPONSE_CODE>1</RESPONSE_CODE><RESPONSE_REASON_CODE>0000</RESPONSE_REASON_CODE><RESPONSE_REASON_TEXT>Approved</RESPONSE_REASON_TEXT><RESPONSE_SUBCODE/><ADDITIONALAMOUNT>0</ADDITIONALAMOUNT><ADDITIONALDATA1/><ADDITIONALDATA2/><ADDITIONALDATA3/><ADDITIONALDATA4/><ADDITIONALDATA5/><AUTHCODE>N+NFUB</AUTHCODE><AUTHORIZEDAMOUNT>1.00</AUTHORIZEDAMOUNT><AVS_RESULT_CODE>P</AVS_RESULT_CODE><BANK_ACCOUNTNAME/><BANK_ACCOUNTTYPE/><BATCHID>0</BATCHID><CARDHOLDER_FIRSTNAME>Longbob</CARDHOLDER_FIRSTNAME><CARDHOLDER_LASTNAME>Longsen</CARDHOLDER_LASTNAME><CARDLEVEL_RESULTS/><CARDTYPE>VI</CARDTYPE><CARD_CODE_RESPONSE_CODE>P</CARD_CODE_RESPONSE_CODE><CASHBACK_AMOUNT>0</CASHBACK_AMOUNT><CAVV_RESPONSE_CODE/><CHECKNUM i:nil="true"/><CODE>0000</CODE><CUSTOMERID/><CUSTOMER_BILL><ADDRESS>1234 My Street</ADDRESS><CITY>Ottawa</CITY><COMPANY>Widgets Inc</COMPANY><COUNTRY>CA</COUNTRY><EMAIL/><EMAILRECEIPT>FALSE</EMAILRECEIPT><FIRSTNAME>Longbob</FIRSTNAME><LASTNAME>Longsen</LASTNAME><PHONE>(555)555-5555</PHONE><STATE>ON</STATE><ZIP>K1C2N6</ZIP></CUSTOMER_BILL><EXPIRYDATE>0911</EXPIRYDATE><GRATUITY>0</GRATUITY><INDUSTRYSPECIFICDATA>P</INDUSTRYSPECIFICDATA><LAST4DIGITS>2224</LAST4DIGITS><LEVEL2_VALID>FALSE</LEVEL2_VALID><LEVEL3_VALID>FALSE</LEVEL3_VALID><MARKETSPECIFICDATA/><METHOD>CC</METHOD><NETWORKCODE/><NETWORKID/><ORDERID>1</ORDERID><PAYMENTID/><RETREFERENCENUM/><SECURENETID>1002550</SECURENETID><SETTLEMENTAMOUNT>1.00</SETTLEMENTAMOUNT><SETTLEMENTDATETIME>09212010233807</SETTLEMENTDATETIME><SYSTEM_TRACENUM/><TRACKTYPE>0</TRACKTYPE><TRANSACTIONAMOUNT>1.00</TRANSACTIONAMOUNT><TRANSACTIONDATETIME>09222010023807</TRANSACTIONDATETIME><TRANSACTIONID>12532160</TRANSACTIONID></TRANSACTIONRESPONSE><VAULTACCOUNTRESPONSE i:nil="true"/><VAULTCUSTOMERRESPONSE i:nil="true"/></GATEWAYRESPONSE>'
  end

  def failed_authorization_response
    '<GATEWAYRESPONSE xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><ASPREPONSE i:nil="true"/><TRANSACTIONRESPONSE><RESPONSE_CODE>2</RESPONSE_CODE><RESPONSE_REASON_CODE>0000</RESPONSE_REASON_CODE><RESPONSE_REASON_TEXT>Declined</RESPONSE_REASON_TEXT><RESPONSE_SUBCODE/><ADDITIONALAMOUNT>0</ADDITIONALAMOUNT><ADDITIONALDATA1/><ADDITIONALDATA2/><ADDITIONALDATA3/><ADDITIONALDATA4/><ADDITIONALDATA5/><AUTHCODE>N+NFUB</AUTHCODE><AUTHORIZEDAMOUNT>1.00</AUTHORIZEDAMOUNT><AVS_RESULT_CODE>P</AVS_RESULT_CODE><BANK_ACCOUNTNAME/><BANK_ACCOUNTTYPE/><BATCHID>0</BATCHID><CARDHOLDER_FIRSTNAME>Longbob</CARDHOLDER_FIRSTNAME><CARDHOLDER_LASTNAME>Longsen</CARDHOLDER_LASTNAME><CARDLEVEL_RESULTS/><CARDTYPE>VI</CARDTYPE><CARD_CODE_RESPONSE_CODE>P</CARD_CODE_RESPONSE_CODE><CASHBACK_AMOUNT>0</CASHBACK_AMOUNT><CAVV_RESPONSE_CODE/><CHECKNUM i:nil="true"/><CODE>0000</CODE><CUSTOMERID/><CUSTOMER_BILL><ADDRESS>1234 My Street</ADDRESS><CITY>Ottawa</CITY><COMPANY>Widgets Inc</COMPANY><COUNTRY>CA</COUNTRY><EMAIL/><EMAILRECEIPT>FALSE</EMAILRECEIPT><FIRSTNAME>Longbob</FIRSTNAME><LASTNAME>Longsen</LASTNAME><PHONE>(555)555-5555</PHONE><STATE>ON</STATE><ZIP>K1C2N6</ZIP></CUSTOMER_BILL><EXPIRYDATE>0911</EXPIRYDATE><GRATUITY>0</GRATUITY><INDUSTRYSPECIFICDATA>P</INDUSTRYSPECIFICDATA><LAST4DIGITS>2224</LAST4DIGITS><LEVEL2_VALID>FALSE</LEVEL2_VALID><LEVEL3_VALID>FALSE</LEVEL3_VALID><MARKETSPECIFICDATA/><METHOD>CC</METHOD><NETWORKCODE/><NETWORKID/><ORDERID>1</ORDERID><PAYMENTID/><RETREFERENCENUM/><SECURENETID>1002550</SECURENETID><SETTLEMENTAMOUNT>1.00</SETTLEMENTAMOUNT><SETTLEMENTDATETIME>09212010233807</SETTLEMENTDATETIME><SYSTEM_TRACENUM/><TRACKTYPE>0</TRACKTYPE><TRANSACTIONAMOUNT>1.00</TRANSACTIONAMOUNT><TRANSACTIONDATETIME>09222010023807</TRANSACTIONDATETIME><TRANSACTIONID>12532160</TRANSACTIONID></TRANSACTIONRESPONSE><VAULTACCOUNTRESPONSE i:nil="true"/><VAULTCUSTOMERRESPONSE i:nil="true"/></GATEWAYRESPONSE>'
  end

  def successful_purchase_response
    '<GATEWAYRESPONSE xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><ASPREPONSE i:nil="true"/><TRANSACTIONRESPONSE><RESPONSE_CODE>1</RESPONSE_CODE><RESPONSE_REASON_CODE>0000</RESPONSE_REASON_CODE><RESPONSE_REASON_TEXT>Approved</RESPONSE_REASON_TEXT><RESPONSE_SUBCODE/><ADDITIONALAMOUNT>0</ADDITIONALAMOUNT><ADDITIONALDATA1/><ADDITIONALDATA2/><ADDITIONALDATA3/><ADDITIONALDATA4/><ADDITIONALDATA5/><AUTHCODE>4TMEWR</AUTHCODE><AUTHORIZEDAMOUNT>1.00</AUTHORIZEDAMOUNT><AVS_RESULT_CODE>P</AVS_RESULT_CODE><BANK_ACCOUNTNAME/><BANK_ACCOUNTTYPE/><BATCHID>0</BATCHID><CARDHOLDER_FIRSTNAME>Longbob</CARDHOLDER_FIRSTNAME><CARDHOLDER_LASTNAME>Longsen</CARDHOLDER_LASTNAME><CARDLEVEL_RESULTS/><CARDTYPE>VI</CARDTYPE><CARD_CODE_RESPONSE_CODE>P</CARD_CODE_RESPONSE_CODE><CASHBACK_AMOUNT>0</CASHBACK_AMOUNT><CAVV_RESPONSE_CODE/><CHECKNUM i:nil="true"/><CODE>0100</CODE><CUSTOMERID/><CUSTOMER_BILL><ADDRESS>1234 My Street</ADDRESS><CITY>Ottawa</CITY><COMPANY>Widgets Inc</COMPANY><COUNTRY>CA</COUNTRY><EMAIL/><EMAILRECEIPT>FALSE</EMAILRECEIPT><FIRSTNAME>Longbob</FIRSTNAME><LASTNAME>Longsen</LASTNAME><PHONE>(555)555-5555</PHONE><STATE>ON</STATE><ZIP>K1C2N6</ZIP></CUSTOMER_BILL><EXPIRYDATE>0911</EXPIRYDATE><GRATUITY>0</GRATUITY><INDUSTRYSPECIFICDATA>P</INDUSTRYSPECIFICDATA><LAST4DIGITS>2224</LAST4DIGITS><LEVEL2_VALID>FALSE</LEVEL2_VALID><LEVEL3_VALID>FALSE</LEVEL3_VALID><MARKETSPECIFICDATA/><METHOD>CC</METHOD><NETWORKCODE/><NETWORKID/><ORDERID>1285170118520000</ORDERID><PAYMENTID/><RETREFERENCENUM/><SECURENETID>1002550</SECURENETID><SETTLEMENTAMOUNT>1.00</SETTLEMENTAMOUNT><SETTLEMENTDATETIME>09222010084144</SETTLEMENTDATETIME><SYSTEM_TRACENUM/><TRACKTYPE>0</TRACKTYPE><TRANSACTIONAMOUNT>1.00</TRANSACTIONAMOUNT><TRANSACTIONDATETIME>09222010114144</TRANSACTIONDATETIME><TRANSACTIONID>12533097</TRANSACTIONID></TRANSACTIONRESPONSE><VAULTACCOUNTRESPONSE i:nil="true"/><VAULTCUSTOMERRESPONSE i:nil="true"/></GATEWAYRESPONSE>'
  end

  def failed_purchase_response
    '<GATEWAYRESPONSE xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><ASPREPONSE i:nil="true"/><TRANSACTIONRESPONSE><RESPONSE_CODE>2</RESPONSE_CODE><RESPONSE_REASON_CODE>0000</RESPONSE_REASON_CODE><RESPONSE_REASON_TEXT>Declined</RESPONSE_REASON_TEXT><RESPONSE_SUBCODE/><ADDITIONALAMOUNT>0</ADDITIONALAMOUNT><ADDITIONALDATA1/><ADDITIONALDATA2/><ADDITIONALDATA3/><ADDITIONALDATA4/><ADDITIONALDATA5/><AUTHCODE>4TMEWR</AUTHCODE><AUTHORIZEDAMOUNT>1.00</AUTHORIZEDAMOUNT><AVS_RESULT_CODE>P</AVS_RESULT_CODE><BANK_ACCOUNTNAME/><BANK_ACCOUNTTYPE/><BATCHID>0</BATCHID><CARDHOLDER_FIRSTNAME>Longbob</CARDHOLDER_FIRSTNAME><CARDHOLDER_LASTNAME>Longsen</CARDHOLDER_LASTNAME><CARDLEVEL_RESULTS/><CARDTYPE>VI</CARDTYPE><CARD_CODE_RESPONSE_CODE>P</CARD_CODE_RESPONSE_CODE><CASHBACK_AMOUNT>0</CASHBACK_AMOUNT><CAVV_RESPONSE_CODE/><CHECKNUM i:nil="true"/><CODE>0100</CODE><CUSTOMERID/><CUSTOMER_BILL><ADDRESS>1234 My Street</ADDRESS><CITY>Ottawa</CITY><COMPANY>Widgets Inc</COMPANY><COUNTRY>CA</COUNTRY><EMAIL/><EMAILRECEIPT>FALSE</EMAILRECEIPT><FIRSTNAME>Longbob</FIRSTNAME><LASTNAME>Longsen</LASTNAME><PHONE>(555)555-5555</PHONE><STATE>ON</STATE><ZIP>K1C2N6</ZIP></CUSTOMER_BILL><EXPIRYDATE>0911</EXPIRYDATE><GRATUITY>0</GRATUITY><INDUSTRYSPECIFICDATA>P</INDUSTRYSPECIFICDATA><LAST4DIGITS>2224</LAST4DIGITS><LEVEL2_VALID>FALSE</LEVEL2_VALID><LEVEL3_VALID>FALSE</LEVEL3_VALID><MARKETSPECIFICDATA/><METHOD>CC</METHOD><NETWORKCODE/><NETWORKID/><ORDERID>1285170118520000</ORDERID><PAYMENTID/><RETREFERENCENUM/><SECURENETID>1002550</SECURENETID><SETTLEMENTAMOUNT>1.00</SETTLEMENTAMOUNT><SETTLEMENTDATETIME>09222010084144</SETTLEMENTDATETIME><SYSTEM_TRACENUM/><TRACKTYPE>0</TRACKTYPE><TRANSACTIONAMOUNT>1.00</TRANSACTIONAMOUNT><TRANSACTIONDATETIME>09222010114144</TRANSACTIONDATETIME><TRANSACTIONID>12533097</TRANSACTIONID></TRANSACTIONRESPONSE><VAULTACCOUNTRESPONSE i:nil="true"/><VAULTCUSTOMERRESPONSE i:nil="true"/></GATEWAYRESPONSE>'
  end

  def successful_capture_response
    '<GATEWAYRESPONSE xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><ASPREPONSE i:nil="true"/><TRANSACTIONRESPONSE><RESPONSE_CODE>1</RESPONSE_CODE><RESPONSE_REASON_CODE>0000</RESPONSE_REASON_CODE><RESPONSE_REASON_TEXT>Approved</RESPONSE_REASON_TEXT><RESPONSE_SUBCODE/><ADDITIONALAMOUNT>0</ADDITIONALAMOUNT><ADDITIONALDATA1/><ADDITIONALDATA2/><ADDITIONALDATA3/><ADDITIONALDATA4/><ADDITIONALDATA5/><AUTHCODE>ND7YPT</AUTHCODE><AUTHORIZEDAMOUNT>1</AUTHORIZEDAMOUNT><AVS_RESULT_CODE>P</AVS_RESULT_CODE><BANK_ACCOUNTNAME/><BANK_ACCOUNTTYPE/><BATCHID>0</BATCHID><CARDHOLDER_FIRSTNAME>Longbob</CARDHOLDER_FIRSTNAME><CARDHOLDER_LASTNAME>Longsen</CARDHOLDER_LASTNAME><CARDLEVEL_RESULTS/><CARDTYPE>VI</CARDTYPE><CARD_CODE_RESPONSE_CODE>P</CARD_CODE_RESPONSE_CODE><CASHBACK_AMOUNT>0</CASHBACK_AMOUNT><CAVV_RESPONSE_CODE/><CHECKNUM i:nil="true"/><CODE>0200</CODE><CUSTOMERID/><CUSTOMER_BILL><ADDRESS/><CITY/><COMPANY/><COUNTRY/><EMAIL/><EMAILRECEIPT>FALSE</EMAILRECEIPT><FIRSTNAME/><LASTNAME/><PHONE/><STATE/><ZIP/></CUSTOMER_BILL><EXPIRYDATE>0911</EXPIRYDATE><GRATUITY>0</GRATUITY><INDUSTRYSPECIFICDATA>P</INDUSTRYSPECIFICDATA><LAST4DIGITS>2224</LAST4DIGITS><LEVEL2_VALID>FALSE</LEVEL2_VALID><LEVEL3_VALID>FALSE</LEVEL3_VALID><MARKETSPECIFICDATA/><METHOD>CC</METHOD><NETWORKCODE/><NETWORKID/><ORDERID>1285170617441000</ORDERID><PAYMENTID>0</PAYMENTID><RETREFERENCENUM/><SECURENETID>1002550</SECURENETID><SETTLEMENTAMOUNT>1</SETTLEMENTAMOUNT><SETTLEMENTDATETIME>09222010115004</SETTLEMENTDATETIME><SYSTEM_TRACENUM/><TRACKTYPE>0</TRACKTYPE><TRANSACTIONAMOUNT>1.00</TRANSACTIONAMOUNT><TRANSACTIONDATETIME>09222010085004</TRANSACTIONDATETIME><TRANSACTIONID>12533132</TRANSACTIONID></TRANSACTIONRESPONSE><VAULTACCOUNTRESPONSE i:nil="true"/><VAULTCUSTOMERRESPONSE i:nil="true"/></GATEWAYRESPONSE>'
  end

  def failed_capture_response
    '<GATEWAYRESPONSE xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><ASPREPONSE i:nil="true"/><TRANSACTIONRESPONSE><RESPONSE_CODE>2</RESPONSE_CODE><RESPONSE_REASON_CODE>0000</RESPONSE_REASON_CODE><RESPONSE_REASON_TEXT>Declined</RESPONSE_REASON_TEXT><RESPONSE_SUBCODE/><ADDITIONALAMOUNT>0</ADDITIONALAMOUNT><ADDITIONALDATA1/><ADDITIONALDATA2/><ADDITIONALDATA3/><ADDITIONALDATA4/><ADDITIONALDATA5/><AUTHCODE>ND7YPT</AUTHCODE><AUTHORIZEDAMOUNT>1</AUTHORIZEDAMOUNT><AVS_RESULT_CODE>P</AVS_RESULT_CODE><BANK_ACCOUNTNAME/><BANK_ACCOUNTTYPE/><BATCHID>0</BATCHID><CARDHOLDER_FIRSTNAME>Longbob</CARDHOLDER_FIRSTNAME><CARDHOLDER_LASTNAME>Longsen</CARDHOLDER_LASTNAME><CARDLEVEL_RESULTS/><CARDTYPE>VI</CARDTYPE><CARD_CODE_RESPONSE_CODE>P</CARD_CODE_RESPONSE_CODE><CASHBACK_AMOUNT>0</CASHBACK_AMOUNT><CAVV_RESPONSE_CODE/><CHECKNUM i:nil="true"/><CODE>0200</CODE><CUSTOMERID/><CUSTOMER_BILL><ADDRESS/><CITY/><COMPANY/><COUNTRY/><EMAIL/><EMAILRECEIPT>FALSE</EMAILRECEIPT><FIRSTNAME/><LASTNAME/><PHONE/><STATE/><ZIP/></CUSTOMER_BILL><EXPIRYDATE>0911</EXPIRYDATE><GRATUITY>0</GRATUITY><INDUSTRYSPECIFICDATA>P</INDUSTRYSPECIFICDATA><LAST4DIGITS>2224</LAST4DIGITS><LEVEL2_VALID>FALSE</LEVEL2_VALID><LEVEL3_VALID>FALSE</LEVEL3_VALID><MARKETSPECIFICDATA/><METHOD>CC</METHOD><NETWORKCODE/><NETWORKID/><ORDERID>1285170617441000</ORDERID><PAYMENTID>0</PAYMENTID><RETREFERENCENUM/><SECURENETID>1002550</SECURENETID><SETTLEMENTAMOUNT>1</SETTLEMENTAMOUNT><SETTLEMENTDATETIME>09222010115004</SETTLEMENTDATETIME><SYSTEM_TRACENUM/><TRACKTYPE>0</TRACKTYPE><TRANSACTIONAMOUNT>1.00</TRANSACTIONAMOUNT><TRANSACTIONDATETIME>09222010085004</TRANSACTIONDATETIME><TRANSACTIONID>12533132</TRANSACTIONID></TRANSACTIONRESPONSE><VAULTACCOUNTRESPONSE i:nil="true"/><VAULTCUSTOMERRESPONSE i:nil="true"/></GATEWAYRESPONSE>'
  end

  def successful_void_response
    '<GATEWAYRESPONSE xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><ASPREPONSE i:nil="true"/><TRANSACTIONRESPONSE><RESPONSE_CODE>1</RESPONSE_CODE><RESPONSE_REASON_CODE>0000</RESPONSE_REASON_CODE><RESPONSE_REASON_TEXT>Approved</RESPONSE_REASON_TEXT><RESPONSE_SUBCODE/><ADDITIONALAMOUNT>0</ADDITIONALAMOUNT><ADDITIONALDATA1/><ADDITIONALDATA2/><ADDITIONALDATA3/><ADDITIONALDATA4/><ADDITIONALDATA5/><AUTHCODE>KF/JI8</AUTHCODE><AUTHORIZEDAMOUNT>1</AUTHORIZEDAMOUNT><AVS_RESULT_CODE>P</AVS_RESULT_CODE><BANK_ACCOUNTNAME/><BANK_ACCOUNTTYPE/><BATCHID>0</BATCHID><CARDHOLDER_FIRSTNAME>Longbob</CARDHOLDER_FIRSTNAME><CARDHOLDER_LASTNAME>Longsen</CARDHOLDER_LASTNAME><CARDLEVEL_RESULTS/><CARDTYPE>VI</CARDTYPE><CARD_CODE_RESPONSE_CODE>P</CARD_CODE_RESPONSE_CODE><CASHBACK_AMOUNT>0</CASHBACK_AMOUNT><CAVV_RESPONSE_CODE/><CHECKNUM i:nil="true"/><CODE>0400</CODE><CUSTOMERID/><CUSTOMER_BILL><ADDRESS/><CITY/><COMPANY/><COUNTRY/><EMAIL/><EMAILRECEIPT>FALSE</EMAILRECEIPT><FIRSTNAME/><LASTNAME/><PHONE/><STATE/><ZIP/></CUSTOMER_BILL><EXPIRYDATE>0911</EXPIRYDATE><GRATUITY>0</GRATUITY><INDUSTRYSPECIFICDATA>P</INDUSTRYSPECIFICDATA><LAST4DIGITS>2224</LAST4DIGITS><LEVEL2_VALID>FALSE</LEVEL2_VALID><LEVEL3_VALID>FALSE</LEVEL3_VALID><MARKETSPECIFICDATA/><METHOD>CC</METHOD><NETWORKCODE/><NETWORKID/><ORDERID>1285171187835000</ORDERID><PAYMENTID>0</PAYMENTID><RETREFERENCENUM/><SECURENETID>1002550</SECURENETID><SETTLEMENTAMOUNT>1</SETTLEMENTAMOUNT><SETTLEMENTDATETIME>09222010115934</SETTLEMENTDATETIME><SYSTEM_TRACENUM/><TRACKTYPE>0</TRACKTYPE><TRANSACTIONAMOUNT>1.00</TRANSACTIONAMOUNT><TRANSACTIONDATETIME>09222010085934</TRANSACTIONDATETIME><TRANSACTIONID>12533174</TRANSACTIONID></TRANSACTIONRESPONSE><VAULTACCOUNTRESPONSE i:nil="true"/><VAULTCUSTOMERRESPONSE i:nil="true"/></GATEWAYRESPONSE>'
  end

  def failed_void_response
    '<GATEWAYRESPONSE xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><ASPREPONSE i:nil="true"/><TRANSACTIONRESPONSE><RESPONSE_CODE>3</RESPONSE_CODE><RESPONSE_REASON_CODE>01R1</RESPONSE_REASON_CODE><RESPONSE_REASON_TEXT>TRANSACTION ID DOES NOT EXIST FOR VOID</RESPONSE_REASON_TEXT><RESPONSE_SUBCODE/><ADDITIONALAMOUNT>0</ADDITIONALAMOUNT><ADDITIONALDATA1 i:nil="true"/><ADDITIONALDATA2 i:nil="true"/><ADDITIONALDATA3 i:nil="true"/><ADDITIONALDATA4 i:nil="true"/><ADDITIONALDATA5 i:nil="true"/><AUTHCODE/><AUTHORIZEDAMOUNT>0</AUTHORIZEDAMOUNT><AVS_RESULT_CODE/><BANK_ACCOUNTNAME i:nil="true"/><BANK_ACCOUNTTYPE i:nil="true"/><BATCHID i:nil="true"/><CARDHOLDER_FIRSTNAME i:nil="true"/><CARDHOLDER_LASTNAME i:nil="true"/><CARDLEVEL_RESULTS i:nil="true"/><CARDTYPE i:nil="true"/><CARD_CODE_RESPONSE_CODE/><CASHBACK_AMOUNT>0</CASHBACK_AMOUNT><CAVV_RESPONSE_CODE/><CHECKNUM i:nil="true"/><CODE>0400</CODE><CUSTOMERID/><CUSTOMER_BILL><ADDRESS/><CITY/><COMPANY/><COUNTRY/><EMAIL/><EMAILRECEIPT>FALSE</EMAILRECEIPT><FIRSTNAME/><LASTNAME/><PHONE/><STATE/><ZIP/></CUSTOMER_BILL><EXPIRYDATE i:nil="true"/><GRATUITY>0</GRATUITY><INDUSTRYSPECIFICDATA i:nil="true"/><LAST4DIGITS i:nil="true"/><LEVEL2_VALID>FALSE</LEVEL2_VALID><LEVEL3_VALID>FALSE</LEVEL3_VALID><MARKETSPECIFICDATA i:nil="true"/><METHOD>CC</METHOD><NETWORKCODE i:nil="true"/><NETWORKID i:nil="true"/><ORDERID>1285171515481000</ORDERID><PAYMENTID i:nil="true"/><RETREFERENCENUM i:nil="true"/><SECURENETID>1002550</SECURENETID><SETTLEMENTAMOUNT>0</SETTLEMENTAMOUNT><SETTLEMENTDATETIME i:nil="true"/><SYSTEM_TRACENUM i:nil="true"/><TRACKTYPE i:nil="true"/><TRANSACTIONAMOUNT>1.00</TRANSACTIONAMOUNT><TRANSACTIONDATETIME i:nil="true"/><TRANSACTIONID>0</TRANSACTIONID></TRANSACTIONRESPONSE><VAULTACCOUNTRESPONSE i:nil="true"/><VAULTCUSTOMERRESPONSE i:nil="true"/></GATEWAYRESPONSE>'
  end

  def successful_refund_response
    '<GATEWAYRESPONSE xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><ASPREPONSE i:nil="true"/><TRANSACTIONRESPONSE><RESPONSE_CODE>1</RESPONSE_CODE><RESPONSE_REASON_CODE>0000</RESPONSE_REASON_CODE><RESPONSE_REASON_TEXT>Approved</RESPONSE_REASON_TEXT><RESPONSE_SUBCODE/><ADDITIONALAMOUNT>0</ADDITIONALAMOUNT><ADDITIONALDATA1/><ADDITIONALDATA2/><ADDITIONALDATA3/><ADDITIONALDATA4/><ADDITIONALDATA5/><AUTHCODE>N+NFUB</AUTHCODE><AUTHORIZEDAMOUNT>1.00</AUTHORIZEDAMOUNT><AVS_RESULT_CODE>P</AVS_RESULT_CODE><BANK_ACCOUNTNAME/><BANK_ACCOUNTTYPE/><BATCHID>0</BATCHID><CARDHOLDER_FIRSTNAME>Longbob</CARDHOLDER_FIRSTNAME><CARDHOLDER_LASTNAME>Longsen</CARDHOLDER_LASTNAME><CARDLEVEL_RESULTS/><CARDTYPE>VI</CARDTYPE><CARD_CODE_RESPONSE_CODE>P</CARD_CODE_RESPONSE_CODE><CASHBACK_AMOUNT>0</CASHBACK_AMOUNT><CAVV_RESPONSE_CODE/><CHECKNUM i:nil="true"/><CODE>0000</CODE><CUSTOMERID/><CUSTOMER_BILL><ADDRESS>1234 My Street</ADDRESS><CITY>Ottawa</CITY><COMPANY>Widgets Inc</COMPANY><COUNTRY>CA</COUNTRY><EMAIL/><EMAILRECEIPT>FALSE</EMAILRECEIPT><FIRSTNAME>Longbob</FIRSTNAME><LASTNAME>Longsen</LASTNAME><PHONE>(555)555-5555</PHONE><STATE>ON</STATE><ZIP>K1C2N6</ZIP></CUSTOMER_BILL><EXPIRYDATE>0911</EXPIRYDATE><GRATUITY>0</GRATUITY><INDUSTRYSPECIFICDATA>P</INDUSTRYSPECIFICDATA><LAST4DIGITS>2224</LAST4DIGITS><LEVEL2_VALID>FALSE</LEVEL2_VALID><LEVEL3_VALID>FALSE</LEVEL3_VALID><MARKETSPECIFICDATA/><METHOD>CC</METHOD><NETWORKCODE/><NETWORKID/><ORDERID>1</ORDERID><PAYMENTID/><RETREFERENCENUM/><SECURENETID>1002550</SECURENETID><SETTLEMENTAMOUNT>1.00</SETTLEMENTAMOUNT><SETTLEMENTDATETIME>09212010233807</SETTLEMENTDATETIME><SYSTEM_TRACENUM/><TRACKTYPE>0</TRACKTYPE><TRANSACTIONAMOUNT>1.00</TRANSACTIONAMOUNT><TRANSACTIONDATETIME>09222010023807</TRANSACTIONDATETIME><TRANSACTIONID>12532160</TRANSACTIONID></TRANSACTIONRESPONSE><VAULTACCOUNTRESPONSE i:nil="true"/><VAULTCUSTOMERRESPONSE i:nil="true"/></GATEWAYRESPONSE>'
  end

  def failed_refund_response
    '<GATEWAYRESPONSE xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><ASPREPONSE i:nil="true"/><TRANSACTIONRESPONSE><RESPONSE_CODE>3</RESPONSE_CODE><RESPONSE_REASON_CODE>01R3</RESPONSE_REASON_CODE><RESPONSE_REASON_TEXT>CREDIT CANNOT BE COMPLETED ON AN UNSETTLED TRANSACTION</RESPONSE_REASON_TEXT><RESPONSE_SUBCODE/><ADDITIONALAMOUNT>0</ADDITIONALAMOUNT><ADDITIONALDATA1 i:nil="true"/><ADDITIONALDATA2 i:nil="true"/><ADDITIONALDATA3 i:nil="true"/><ADDITIONALDATA4 i:nil="true"/><ADDITIONALDATA5 i:nil="true"/><AUTHCODE/><AUTHORIZEDAMOUNT>0</AUTHORIZEDAMOUNT><AVS_RESULT_CODE/><BANK_ACCOUNTNAME i:nil="true"/><BANK_ACCOUNTTYPE i:nil="true"/><BATCHID i:nil="true"/><CARDHOLDER_FIRSTNAME i:nil="true"/><CARDHOLDER_LASTNAME i:nil="true"/><CARDLEVEL_RESULTS i:nil="true"/><CARDTYPE i:nil="true"/><CARD_CODE_RESPONSE_CODE/><CASHBACK_AMOUNT>0</CASHBACK_AMOUNT><CAVV_RESPONSE_CODE/><CHECKNUM i:nil="true"/><CODE>0500</CODE><CUSTOMERID/><CUSTOMER_BILL><ADDRESS/><CITY/><COMPANY/><COUNTRY/><EMAIL/><EMAILRECEIPT>FALSE</EMAILRECEIPT><FIRSTNAME/><LASTNAME/><PHONE/><STATE/><ZIP/></CUSTOMER_BILL><EXPIRYDATE i:nil="true"/><GRATUITY>0</GRATUITY><INDUSTRYSPECIFICDATA i:nil="true"/><LAST4DIGITS i:nil="true"/><LEVEL2_VALID>FALSE</LEVEL2_VALID><LEVEL3_VALID>FALSE</LEVEL3_VALID><MARKETSPECIFICDATA i:nil="true"/><METHOD>CC</METHOD><NETWORKCODE i:nil="true"/><NETWORKID i:nil="true"/><ORDERID>1285171984419000</ORDERID><PAYMENTID i:nil="true"/><RETREFERENCENUM i:nil="true"/><SECURENETID>1002550</SECURENETID><SETTLEMENTAMOUNT>0</SETTLEMENTAMOUNT><SETTLEMENTDATETIME i:nil="true"/><SYSTEM_TRACENUM i:nil="true"/><TRACKTYPE i:nil="true"/><TRANSACTIONAMOUNT>1.00</TRANSACTIONAMOUNT><TRANSACTIONDATETIME i:nil="true"/><TRANSACTIONID>0</TRANSACTIONID></TRANSACTIONRESPONSE><VAULTACCOUNTRESPONSE i:nil="true"/><VAULTCUSTOMERRESPONSE i:nil="true"/></GATEWAYRESPONSE>'
  end

  def pre_scrubbed
    <<~REQUEST
      opening connection to certify.securenet.com:443...
      opened
      starting SSL for certify.securenet.com:443...
      SSL established
      <- "POST /API/gateway.svc/webHttp/ProcessTransaction HTTP/1.1\r\nContent-Type: text/xml\r\nAccept-Encoding: gzip;q=1.0,deflate;q=0.6,identity;q=0.3\r\nAccept: */*\r\nUser-Agent: Ruby\r\nConnection: close\r\nHost: certify.securenet.com\r\nContent-Length: 1044\r\n\r\n"
      <- "<?xml version="1.0" encoding="UTF-8"?><TRANSACTION xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><AMOUNT>1.00</AMOUNT><CARD><CARDCODE>123</CARDCODE><CARDNUMBER>4000100011112224</CARDNUMBER><EXPDATE>0919</EXPDATE></CARD><CODE>0100</CODE><CUSTOMER_BILL><ADDRESS>456 My Street</ADDRESS><CITY>Ottawa</CITY><COMPANY>Widgets Inc</COMPANY><COUNTRY>CA</COUNTRY><FIRSTNAME>Longbob</FIRSTNAME><LASTNAME>Longsen</LASTNAME><PHONE>(555)555-5555</PHONE><STATE>ON</STATE><ZIP>K1C2N6</ZIP></CUSTOMER_BILL><CUSTOMER_SHIP i:nil="true"></CUSTOMER_SHIP><DCI>0</DCI><INSTALLMENT_SEQUENCENUM>1</INSTALLMENT_SEQUENCENUM><MERCHANT_KEY><GROUPID>0</GROUPID><SECUREKEY>BI8gL8HO1dKP</SECUREKEY><SECURENETID>7001218</SECURENETID></MERCHANT_KEY><METHOD>CC</METHOD><NOTE>Store Purchase</NOTE><ORDERID>1519921868962609</ORDERID><OVERRIDE_FROM>0</OVERRIDE_FROM><RETAIL_LANENUM>0</RETAIL_LANENUM><TEST>TRUE</TEST><TOTAL_INSTALLMENTCOUNT>0</TOTAL_INSTALLMENTCOUNT><TRANSACTION_SERVICE>0</TRANSACTION_SERVICE></TRANSACTION>"
      -> "HTTP/1.1 200 OK\r\n"
      -> "Content-Length: 2547\r\n"
      -> "Content-Type: application/xml; charset=utf-8\r\n"
      -> "X-Powered-By: ASP.NET\r\n"
      -> "Date: Thu, 01 Mar 2018 16:31:01 GMT\r\n"
      -> "Connection: close\r\n"
      -> "Set-Cookie: TS01e56b0e=010bfb2c76b6671aabf6f176a4e5aefd8e7a6ce7f697d82dfcfd424edede4ae7d4dba7557a4a7a13a539cfc1c5c061e08d5040811a; Path=/\r\n"
      -> "\r\n"
      reading 2547 bytes...
      -> "<GATEWAYRESPONSE xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><ABRESPONSE i:nil="true"/><TRANSACTIONRESPONSE><RESPONSE_CODE>1</RESPONSE_CODE><RESPONSE_REASON_CODE>0000</RESPONSE_REASON_CODE><RESPONSE_REASON_TEXT>Approved</RESPONSE_REASON_TEXT><RESPONSE_SUBCODE/><ADDITIONALAMOUNT>0</ADDITIONALAMOUNT><ADDITIONALDATA1/><ADDITIONALDATA2/><ADDITIONALDATA3/><ADDITIONALDATA4/><ADDITIONALDATA5/><AUTHCODE>JUJQLQ</AUTHCODE><AUTHORIZATIONMODE i:nil="true"/><AUTHORIZEDAMOUNT>1.00</AUTHORIZEDAMOUNT><AVS_RESULT_CODE>Y</AVS_RESULT_CODE><BANK_ACCOUNTNAME/><BANK_ACCOUNTTYPE/><BATCHID>0</BATCHID><CALLID/><CARDENTRYMODE i:nil="true"/><CARDHOLDERVERIFICATION i:nil="true"/><CARDHOLDER_FIRSTNAME>Longbob</CARDHOLDER_FIRSTNAME><CARDHOLDER_LASTNAME>Longsen</CARDHOLDER_LASTNAME><CARDLEVEL_RESULTS/><CARDTYPE>VI</CARDTYPE><CARD_CODE_RESPONSE_CODE>M</CARD_CODE_RESPONSE_CODE><CASHBACK_AMOUNT>0</CASHBACK_AMOUNT><CATINDICATOR>0</CATINDICATOR><CAVV_RESPONSE_CODE/><CHECKNUM i:nil="true"/><CODE>0100</CODE><CUSTOMERID/><CUSTOMER_BILL><ADDRESS>456 My Street</ADDRESS><CITY>Ottawa</CITY><COMPANY>Widgets Inc</COMPANY><COUNTRY>CA</COUNTRY><EMAIL/><EMAILRECEIPT>FALSE</EMAILRECEIPT><FIRSTNAME>Longbob</FIRSTNAME><LASTNAME>Longsen</LASTNAME><PHONE>(555)555-5555</PHONE><STATE>ON</STATE><ZIP>K1C2N6</ZIP></CUSTOMER_BILL><DYNAMICMCC i:nil="true"/><EMVRESPONSE><ISSUERAUTHENTICATIONDATA i:nil="true"/><ISSUERSCRIPTTEMPLATE1 i:nil="true"/><ISSUERSCRIPTTEMPLATE2 i:nil="true"/></EMVRESPONSE><EXPIRYDATE>0919</EXPIRYDATE><GRATUITY>0</GRATUITY><INDUSTRYSPECIFICDATA>P</INDUSTRYSPECIFICDATA><INVOICEDESCRIPTION i:nil="true"/><LAST4DIGITS>2224</LAST4DIGITS><LEVEL2_VALID>FALSE</LEVEL2_VALID><LEVEL3_VALID>FALSE</LEVEL3_VALID><MARKETSPECIFICDATA/><METHOD>CC</METHOD><NETWORKCODE/><NETWORKID/><NOTES>Store Purchase</NOTES><ORDERID>1519921868962609</ORDERID><PAYMENTID/><RETREFERENCENUM/><RISK_CATEGORY i:nil="true"/><RISK_REASON1 i:nil="true"/><RISK_REASON2 i:nil="true"/><RISK_REASON3 i:nil="true"/><RISK_REASON4 i:nil="true"/><RISK_REASON5 i:nil="true"/><SECURENETID>7001218</SECURENETID><SETTLEMENTAMOUNT>1.00</SETTLEMENTAMOUNT><SETTLEMENTDATETIME>03012018113101</SETTLEMENTDATETIME><SOFTDESCRIPTOR/><SYSTEM_TRACENUM/><TRACKTYPE>0</TRACKTYPE><TRANSACTIONAMOUNT>1.00</TRANSACTIONAMOUNT><TRANSACTIONDATETIME>03012018113101</TRANSACTIONDATETIME><TRANSACTIONID>116186071</TRANSACTIONID><USERDEFINED i:nil="true"/></TRANSACTIONRESPONSE><VAULTACCOUNTRESPONSE i:nil="true"/><VAULTCUSTOMERRESPONSE i:nil="true"/></GATEWAYRESPONSE>"
      read 2547 bytes
      Conn close
    REQUEST
  end

  def post_scrubbed
    <<~REQUEST
      opening connection to certify.securenet.com:443...
      opened
      starting SSL for certify.securenet.com:443...
      SSL established
      <- "POST /API/gateway.svc/webHttp/ProcessTransaction HTTP/1.1\r\nContent-Type: text/xml\r\nAccept-Encoding: gzip;q=1.0,deflate;q=0.6,identity;q=0.3\r\nAccept: */*\r\nUser-Agent: Ruby\r\nConnection: close\r\nHost: certify.securenet.com\r\nContent-Length: 1044\r\n\r\n"
      <- "<?xml version="1.0" encoding="UTF-8"?><TRANSACTION xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><AMOUNT>1.00</AMOUNT><CARD><CARDCODE>[FILTERED]</CARDCODE><CARDNUMBER>[FILTERED]</CARDNUMBER><EXPDATE>0919</EXPDATE></CARD><CODE>0100</CODE><CUSTOMER_BILL><ADDRESS>456 My Street</ADDRESS><CITY>Ottawa</CITY><COMPANY>Widgets Inc</COMPANY><COUNTRY>CA</COUNTRY><FIRSTNAME>Longbob</FIRSTNAME><LASTNAME>Longsen</LASTNAME><PHONE>(555)555-5555</PHONE><STATE>ON</STATE><ZIP>K1C2N6</ZIP></CUSTOMER_BILL><CUSTOMER_SHIP i:nil="true"></CUSTOMER_SHIP><DCI>0</DCI><INSTALLMENT_SEQUENCENUM>1</INSTALLMENT_SEQUENCENUM><MERCHANT_KEY><GROUPID>0</GROUPID><SECUREKEY>[FILTERED]</SECUREKEY><SECURENETID>7001218</SECURENETID></MERCHANT_KEY><METHOD>CC</METHOD><NOTE>Store Purchase</NOTE><ORDERID>1519921868962609</ORDERID><OVERRIDE_FROM>0</OVERRIDE_FROM><RETAIL_LANENUM>0</RETAIL_LANENUM><TEST>TRUE</TEST><TOTAL_INSTALLMENTCOUNT>0</TOTAL_INSTALLMENTCOUNT><TRANSACTION_SERVICE>0</TRANSACTION_SERVICE></TRANSACTION>"
      -> "HTTP/1.1 200 OK\r\n"
      -> "Content-Length: 2547\r\n"
      -> "Content-Type: application/xml; charset=utf-8\r\n"
      -> "X-Powered-By: ASP.NET\r\n"
      -> "Date: Thu, 01 Mar 2018 16:31:01 GMT\r\n"
      -> "Connection: close\r\n"
      -> "Set-Cookie: TS01e56b0e=010bfb2c76b6671aabf6f176a4e5aefd8e7a6ce7f697d82dfcfd424edede4ae7d4dba7557a4a7a13a539cfc1c5c061e08d5040811a; Path=/\r\n"
      -> "\r\n"
      reading 2547 bytes...
      -> "<GATEWAYRESPONSE xmlns="http://gateway.securenet.com/API/Contracts" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><ABRESPONSE i:nil="true"/><TRANSACTIONRESPONSE><RESPONSE_CODE>1</RESPONSE_CODE><RESPONSE_REASON_CODE>0000</RESPONSE_REASON_CODE><RESPONSE_REASON_TEXT>Approved</RESPONSE_REASON_TEXT><RESPONSE_SUBCODE/><ADDITIONALAMOUNT>0</ADDITIONALAMOUNT><ADDITIONALDATA1/><ADDITIONALDATA2/><ADDITIONALDATA3/><ADDITIONALDATA4/><ADDITIONALDATA5/><AUTHCODE>JUJQLQ</AUTHCODE><AUTHORIZATIONMODE i:nil="true"/><AUTHORIZEDAMOUNT>1.00</AUTHORIZEDAMOUNT><AVS_RESULT_CODE>Y</AVS_RESULT_CODE><BANK_ACCOUNTNAME/><BANK_ACCOUNTTYPE/><BATCHID>0</BATCHID><CALLID/><CARDENTRYMODE i:nil="true"/><CARDHOLDERVERIFICATION i:nil="true"/><CARDHOLDER_FIRSTNAME>Longbob</CARDHOLDER_FIRSTNAME><CARDHOLDER_LASTNAME>Longsen</CARDHOLDER_LASTNAME><CARDLEVEL_RESULTS/><CARDTYPE>VI</CARDTYPE><CARD_CODE_RESPONSE_CODE>M</CARD_CODE_RESPONSE_CODE><CASHBACK_AMOUNT>0</CASHBACK_AMOUNT><CATINDICATOR>0</CATINDICATOR><CAVV_RESPONSE_CODE/><CHECKNUM i:nil="true"/><CODE>0100</CODE><CUSTOMERID/><CUSTOMER_BILL><ADDRESS>456 My Street</ADDRESS><CITY>Ottawa</CITY><COMPANY>Widgets Inc</COMPANY><COUNTRY>CA</COUNTRY><EMAIL/><EMAILRECEIPT>FALSE</EMAILRECEIPT><FIRSTNAME>Longbob</FIRSTNAME><LASTNAME>Longsen</LASTNAME><PHONE>(555)555-5555</PHONE><STATE>ON</STATE><ZIP>K1C2N6</ZIP></CUSTOMER_BILL><DYNAMICMCC i:nil="true"/><EMVRESPONSE><ISSUERAUTHENTICATIONDATA i:nil="true"/><ISSUERSCRIPTTEMPLATE1 i:nil="true"/><ISSUERSCRIPTTEMPLATE2 i:nil="true"/></EMVRESPONSE><EXPIRYDATE>0919</EXPIRYDATE><GRATUITY>0</GRATUITY><INDUSTRYSPECIFICDATA>P</INDUSTRYSPECIFICDATA><INVOICEDESCRIPTION i:nil="true"/><LAST4DIGITS>2224</LAST4DIGITS><LEVEL2_VALID>FALSE</LEVEL2_VALID><LEVEL3_VALID>FALSE</LEVEL3_VALID><MARKETSPECIFICDATA/><METHOD>CC</METHOD><NETWORKCODE/><NETWORKID/><NOTES>Store Purchase</NOTES><ORDERID>1519921868962609</ORDERID><PAYMENTID/><RETREFERENCENUM/><RISK_CATEGORY i:nil="true"/><RISK_REASON1 i:nil="true"/><RISK_REASON2 i:nil="true"/><RISK_REASON3 i:nil="true"/><RISK_REASON4 i:nil="true"/><RISK_REASON5 i:nil="true"/><SECURENETID>7001218</SECURENETID><SETTLEMENTAMOUNT>1.00</SETTLEMENTAMOUNT><SETTLEMENTDATETIME>03012018113101</SETTLEMENTDATETIME><SOFTDESCRIPTOR/><SYSTEM_TRACENUM/><TRACKTYPE>0</TRACKTYPE><TRANSACTIONAMOUNT>1.00</TRANSACTIONAMOUNT><TRANSACTIONDATETIME>03012018113101</TRANSACTIONDATETIME><TRANSACTIONID>116186071</TRANSACTIONID><USERDEFINED i:nil="true"/></TRANSACTIONRESPONSE><VAULTACCOUNTRESPONSE i:nil="true"/><VAULTCUSTOMERRESPONSE i:nil="true"/></GATEWAYRESPONSE>"
      read 2547 bytes
      Conn close
    REQUEST
  end
end
