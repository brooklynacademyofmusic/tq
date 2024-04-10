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

// CrediteeTypesCreateReader is a Reader for the CrediteeTypesCreate structure.
type CrediteeTypesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CrediteeTypesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCrediteeTypesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /ReferenceData/CrediteeTypes] CrediteeTypes_Create", response, response.Code())
	}
}

// NewCrediteeTypesCreateOK creates a CrediteeTypesCreateOK with default headers values
func NewCrediteeTypesCreateOK() *CrediteeTypesCreateOK {
	return &CrediteeTypesCreateOK{}
}

/*
CrediteeTypesCreateOK describes a response with status code 200, with default header values.

OK
*/
type CrediteeTypesCreateOK struct {
	Payload *models.CrediteeType
}

// IsSuccess returns true when this creditee types create o k response has a 2xx status code
func (o *CrediteeTypesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this creditee types create o k response has a 3xx status code
func (o *CrediteeTypesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this creditee types create o k response has a 4xx status code
func (o *CrediteeTypesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this creditee types create o k response has a 5xx status code
func (o *CrediteeTypesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this creditee types create o k response a status code equal to that given
func (o *CrediteeTypesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the creditee types create o k response
func (o *CrediteeTypesCreateOK) Code() int {
	return 200
}

func (o *CrediteeTypesCreateOK) Error() string {
	return fmt.Sprintf("[POST /ReferenceData/CrediteeTypes][%d] crediteeTypesCreateOK  %+v", 200, o.Payload)
}

func (o *CrediteeTypesCreateOK) String() string {
	return fmt.Sprintf("[POST /ReferenceData/CrediteeTypes][%d] crediteeTypesCreateOK  %+v", 200, o.Payload)
}

func (o *CrediteeTypesCreateOK) GetPayload() *models.CrediteeType {
	return o.Payload
}

func (o *CrediteeTypesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CrediteeType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}