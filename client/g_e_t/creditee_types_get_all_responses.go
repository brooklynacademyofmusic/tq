// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// CrediteeTypesGetAllReader is a Reader for the CrediteeTypesGetAll structure.
type CrediteeTypesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CrediteeTypesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCrediteeTypesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCrediteeTypesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCrediteeTypesGetAllOK creates a CrediteeTypesGetAllOK with default headers values
func NewCrediteeTypesGetAllOK() *CrediteeTypesGetAllOK {
	return &CrediteeTypesGetAllOK{}
}

/*
CrediteeTypesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type CrediteeTypesGetAllOK struct {
	Payload []*models.CrediteeType
}

// IsSuccess returns true when this creditee types get all o k response has a 2xx status code
func (o *CrediteeTypesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this creditee types get all o k response has a 3xx status code
func (o *CrediteeTypesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this creditee types get all o k response has a 4xx status code
func (o *CrediteeTypesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this creditee types get all o k response has a 5xx status code
func (o *CrediteeTypesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this creditee types get all o k response a status code equal to that given
func (o *CrediteeTypesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the creditee types get all o k response
func (o *CrediteeTypesGetAllOK) Code() int {
	return 200
}

func (o *CrediteeTypesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CrediteeTypes][%d] crediteeTypesGetAllOK %s", 200, payload)
}

func (o *CrediteeTypesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CrediteeTypes][%d] crediteeTypesGetAllOK %s", 200, payload)
}

func (o *CrediteeTypesGetAllOK) GetPayload() []*models.CrediteeType {
	return o.Payload
}

func (o *CrediteeTypesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCrediteeTypesGetAllDefault creates a CrediteeTypesGetAllDefault with default headers values
func NewCrediteeTypesGetAllDefault(code int) *CrediteeTypesGetAllDefault {
	return &CrediteeTypesGetAllDefault{
		_statusCode: code,
	}
}

/*
CrediteeTypesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type CrediteeTypesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this creditee types get all default response has a 2xx status code
func (o *CrediteeTypesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this creditee types get all default response has a 3xx status code
func (o *CrediteeTypesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this creditee types get all default response has a 4xx status code
func (o *CrediteeTypesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this creditee types get all default response has a 5xx status code
func (o *CrediteeTypesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this creditee types get all default response a status code equal to that given
func (o *CrediteeTypesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the creditee types get all default response
func (o *CrediteeTypesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *CrediteeTypesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CrediteeTypes][%d] CrediteeTypes_GetAll default %s", o._statusCode, payload)
}

func (o *CrediteeTypesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CrediteeTypes][%d] CrediteeTypes_GetAll default %s", o._statusCode, payload)
}

func (o *CrediteeTypesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CrediteeTypesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
