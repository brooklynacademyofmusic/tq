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

// CurrencyTypesGetAllReader is a Reader for the CurrencyTypesGetAll structure.
type CurrencyTypesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CurrencyTypesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCurrencyTypesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCurrencyTypesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCurrencyTypesGetAllOK creates a CurrencyTypesGetAllOK with default headers values
func NewCurrencyTypesGetAllOK() *CurrencyTypesGetAllOK {
	return &CurrencyTypesGetAllOK{}
}

/*
CurrencyTypesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type CurrencyTypesGetAllOK struct {
	Payload []*models.CurrencyType
}

// IsSuccess returns true when this currency types get all o k response has a 2xx status code
func (o *CurrencyTypesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this currency types get all o k response has a 3xx status code
func (o *CurrencyTypesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this currency types get all o k response has a 4xx status code
func (o *CurrencyTypesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this currency types get all o k response has a 5xx status code
func (o *CurrencyTypesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this currency types get all o k response a status code equal to that given
func (o *CurrencyTypesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the currency types get all o k response
func (o *CurrencyTypesGetAllOK) Code() int {
	return 200
}

func (o *CurrencyTypesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CurrencyTypes][%d] currencyTypesGetAllOK %s", 200, payload)
}

func (o *CurrencyTypesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CurrencyTypes][%d] currencyTypesGetAllOK %s", 200, payload)
}

func (o *CurrencyTypesGetAllOK) GetPayload() []*models.CurrencyType {
	return o.Payload
}

func (o *CurrencyTypesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCurrencyTypesGetAllDefault creates a CurrencyTypesGetAllDefault with default headers values
func NewCurrencyTypesGetAllDefault(code int) *CurrencyTypesGetAllDefault {
	return &CurrencyTypesGetAllDefault{
		_statusCode: code,
	}
}

/*
CurrencyTypesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type CurrencyTypesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this currency types get all default response has a 2xx status code
func (o *CurrencyTypesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this currency types get all default response has a 3xx status code
func (o *CurrencyTypesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this currency types get all default response has a 4xx status code
func (o *CurrencyTypesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this currency types get all default response has a 5xx status code
func (o *CurrencyTypesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this currency types get all default response a status code equal to that given
func (o *CurrencyTypesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the currency types get all default response
func (o *CurrencyTypesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *CurrencyTypesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CurrencyTypes][%d] CurrencyTypes_GetAll default %s", o._statusCode, payload)
}

func (o *CurrencyTypesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CurrencyTypes][%d] CurrencyTypes_GetAll default %s", o._statusCode, payload)
}

func (o *CurrencyTypesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CurrencyTypesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
