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

// PaymentTypesGetReader is a Reader for the PaymentTypesGet structure.
type PaymentTypesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentTypesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentTypesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/PaymentTypes/{id}] PaymentTypes_Get", response, response.Code())
	}
}

// NewPaymentTypesGetOK creates a PaymentTypesGetOK with default headers values
func NewPaymentTypesGetOK() *PaymentTypesGetOK {
	return &PaymentTypesGetOK{}
}

/*
PaymentTypesGetOK describes a response with status code 200, with default header values.

OK
*/
type PaymentTypesGetOK struct {
	Payload *models.PaymentType
}

// IsSuccess returns true when this payment types get o k response has a 2xx status code
func (o *PaymentTypesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment types get o k response has a 3xx status code
func (o *PaymentTypesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment types get o k response has a 4xx status code
func (o *PaymentTypesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment types get o k response has a 5xx status code
func (o *PaymentTypesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payment types get o k response a status code equal to that given
func (o *PaymentTypesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payment types get o k response
func (o *PaymentTypesGetOK) Code() int {
	return 200
}

func (o *PaymentTypesGetOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/PaymentTypes/{id}][%d] paymentTypesGetOK  %+v", 200, o.Payload)
}

func (o *PaymentTypesGetOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/PaymentTypes/{id}][%d] paymentTypesGetOK  %+v", 200, o.Payload)
}

func (o *PaymentTypesGetOK) GetPayload() *models.PaymentType {
	return o.Payload
}

func (o *PaymentTypesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PaymentType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}