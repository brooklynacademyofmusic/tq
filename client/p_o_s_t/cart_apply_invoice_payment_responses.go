// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// CartApplyInvoicePaymentReader is a Reader for the CartApplyInvoicePayment structure.
type CartApplyInvoicePaymentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CartApplyInvoicePaymentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCartApplyInvoicePaymentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /Web/Cart/{sessionKey}/Payments/Invoice] Cart_ApplyInvoicePayment", response, response.Code())
	}
}

// NewCartApplyInvoicePaymentOK creates a CartApplyInvoicePaymentOK with default headers values
func NewCartApplyInvoicePaymentOK() *CartApplyInvoicePaymentOK {
	return &CartApplyInvoicePaymentOK{}
}

/*
CartApplyInvoicePaymentOK describes a response with status code 200, with default header values.

OK
*/
type CartApplyInvoicePaymentOK struct {
	Payload *models.ApplyPaymentResponse
}

// IsSuccess returns true when this cart apply invoice payment o k response has a 2xx status code
func (o *CartApplyInvoicePaymentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cart apply invoice payment o k response has a 3xx status code
func (o *CartApplyInvoicePaymentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cart apply invoice payment o k response has a 4xx status code
func (o *CartApplyInvoicePaymentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this cart apply invoice payment o k response has a 5xx status code
func (o *CartApplyInvoicePaymentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this cart apply invoice payment o k response a status code equal to that given
func (o *CartApplyInvoicePaymentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the cart apply invoice payment o k response
func (o *CartApplyInvoicePaymentOK) Code() int {
	return 200
}

func (o *CartApplyInvoicePaymentOK) Error() string {
	return fmt.Sprintf("[POST /Web/Cart/{sessionKey}/Payments/Invoice][%d] cartApplyInvoicePaymentOK  %+v", 200, o.Payload)
}

func (o *CartApplyInvoicePaymentOK) String() string {
	return fmt.Sprintf("[POST /Web/Cart/{sessionKey}/Payments/Invoice][%d] cartApplyInvoicePaymentOK  %+v", 200, o.Payload)
}

func (o *CartApplyInvoicePaymentOK) GetPayload() *models.ApplyPaymentResponse {
	return o.Payload
}

func (o *CartApplyInvoicePaymentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ApplyPaymentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}