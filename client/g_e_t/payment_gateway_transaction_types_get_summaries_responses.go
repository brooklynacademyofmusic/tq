// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// PaymentGatewayTransactionTypesGetSummariesReader is a Reader for the PaymentGatewayTransactionTypesGetSummaries structure.
type PaymentGatewayTransactionTypesGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentGatewayTransactionTypesGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentGatewayTransactionTypesGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/PaymentGatewayTransactionTypes/Summary] PaymentGatewayTransactionTypes_GetSummaries", response, response.Code())
	}
}

// NewPaymentGatewayTransactionTypesGetSummariesOK creates a PaymentGatewayTransactionTypesGetSummariesOK with default headers values
func NewPaymentGatewayTransactionTypesGetSummariesOK() *PaymentGatewayTransactionTypesGetSummariesOK {
	return &PaymentGatewayTransactionTypesGetSummariesOK{}
}

/*
PaymentGatewayTransactionTypesGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type PaymentGatewayTransactionTypesGetSummariesOK struct {
	Payload []*models.PaymentGatewayTransactionTypeSummary
}

// IsSuccess returns true when this payment gateway transaction types get summaries o k response has a 2xx status code
func (o *PaymentGatewayTransactionTypesGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment gateway transaction types get summaries o k response has a 3xx status code
func (o *PaymentGatewayTransactionTypesGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment gateway transaction types get summaries o k response has a 4xx status code
func (o *PaymentGatewayTransactionTypesGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment gateway transaction types get summaries o k response has a 5xx status code
func (o *PaymentGatewayTransactionTypesGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payment gateway transaction types get summaries o k response a status code equal to that given
func (o *PaymentGatewayTransactionTypesGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payment gateway transaction types get summaries o k response
func (o *PaymentGatewayTransactionTypesGetSummariesOK) Code() int {
	return 200
}

func (o *PaymentGatewayTransactionTypesGetSummariesOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/PaymentGatewayTransactionTypes/Summary][%d] paymentGatewayTransactionTypesGetSummariesOK  %+v", 200, o.Payload)
}

func (o *PaymentGatewayTransactionTypesGetSummariesOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/PaymentGatewayTransactionTypes/Summary][%d] paymentGatewayTransactionTypesGetSummariesOK  %+v", 200, o.Payload)
}

func (o *PaymentGatewayTransactionTypesGetSummariesOK) GetPayload() []*models.PaymentGatewayTransactionTypeSummary {
	return o.Payload
}

func (o *PaymentGatewayTransactionTypesGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}