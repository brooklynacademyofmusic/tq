// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// BillingTypesUpdateReader is a Reader for the BillingTypesUpdate structure.
type BillingTypesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BillingTypesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewBillingTypesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[PUT /ReferenceData/BillingTypes/{id}] BillingTypes_Update", response, response.Code())
	}
}

// NewBillingTypesUpdateOK creates a BillingTypesUpdateOK with default headers values
func NewBillingTypesUpdateOK() *BillingTypesUpdateOK {
	return &BillingTypesUpdateOK{}
}

/*
BillingTypesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type BillingTypesUpdateOK struct {
	Payload *models.BillingType
}

// IsSuccess returns true when this billing types update o k response has a 2xx status code
func (o *BillingTypesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this billing types update o k response has a 3xx status code
func (o *BillingTypesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this billing types update o k response has a 4xx status code
func (o *BillingTypesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this billing types update o k response has a 5xx status code
func (o *BillingTypesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this billing types update o k response a status code equal to that given
func (o *BillingTypesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the billing types update o k response
func (o *BillingTypesUpdateOK) Code() int {
	return 200
}

func (o *BillingTypesUpdateOK) Error() string {
	return fmt.Sprintf("[PUT /ReferenceData/BillingTypes/{id}][%d] billingTypesUpdateOK  %+v", 200, o.Payload)
}

func (o *BillingTypesUpdateOK) String() string {
	return fmt.Sprintf("[PUT /ReferenceData/BillingTypes/{id}][%d] billingTypesUpdateOK  %+v", 200, o.Payload)
}

func (o *BillingTypesUpdateOK) GetPayload() *models.BillingType {
	return o.Payload
}

func (o *BillingTypesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BillingType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}