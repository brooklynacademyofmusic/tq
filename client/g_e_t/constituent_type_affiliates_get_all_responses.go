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

// ConstituentTypeAffiliatesGetAllReader is a Reader for the ConstituentTypeAffiliatesGetAll structure.
type ConstituentTypeAffiliatesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ConstituentTypeAffiliatesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewConstituentTypeAffiliatesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewConstituentTypeAffiliatesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewConstituentTypeAffiliatesGetAllOK creates a ConstituentTypeAffiliatesGetAllOK with default headers values
func NewConstituentTypeAffiliatesGetAllOK() *ConstituentTypeAffiliatesGetAllOK {
	return &ConstituentTypeAffiliatesGetAllOK{}
}

/*
ConstituentTypeAffiliatesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type ConstituentTypeAffiliatesGetAllOK struct {
	Payload []*models.ConstituentTypeAffiliate
}

// IsSuccess returns true when this constituent type affiliates get all o k response has a 2xx status code
func (o *ConstituentTypeAffiliatesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this constituent type affiliates get all o k response has a 3xx status code
func (o *ConstituentTypeAffiliatesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this constituent type affiliates get all o k response has a 4xx status code
func (o *ConstituentTypeAffiliatesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this constituent type affiliates get all o k response has a 5xx status code
func (o *ConstituentTypeAffiliatesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this constituent type affiliates get all o k response a status code equal to that given
func (o *ConstituentTypeAffiliatesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the constituent type affiliates get all o k response
func (o *ConstituentTypeAffiliatesGetAllOK) Code() int {
	return 200
}

func (o *ConstituentTypeAffiliatesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ConstituentTypeAffiliates][%d] constituentTypeAffiliatesGetAllOK %s", 200, payload)
}

func (o *ConstituentTypeAffiliatesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ConstituentTypeAffiliates][%d] constituentTypeAffiliatesGetAllOK %s", 200, payload)
}

func (o *ConstituentTypeAffiliatesGetAllOK) GetPayload() []*models.ConstituentTypeAffiliate {
	return o.Payload
}

func (o *ConstituentTypeAffiliatesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConstituentTypeAffiliatesGetAllDefault creates a ConstituentTypeAffiliatesGetAllDefault with default headers values
func NewConstituentTypeAffiliatesGetAllDefault(code int) *ConstituentTypeAffiliatesGetAllDefault {
	return &ConstituentTypeAffiliatesGetAllDefault{
		_statusCode: code,
	}
}

/*
ConstituentTypeAffiliatesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type ConstituentTypeAffiliatesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this constituent type affiliates get all default response has a 2xx status code
func (o *ConstituentTypeAffiliatesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this constituent type affiliates get all default response has a 3xx status code
func (o *ConstituentTypeAffiliatesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this constituent type affiliates get all default response has a 4xx status code
func (o *ConstituentTypeAffiliatesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this constituent type affiliates get all default response has a 5xx status code
func (o *ConstituentTypeAffiliatesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this constituent type affiliates get all default response a status code equal to that given
func (o *ConstituentTypeAffiliatesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the constituent type affiliates get all default response
func (o *ConstituentTypeAffiliatesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *ConstituentTypeAffiliatesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ConstituentTypeAffiliates][%d] ConstituentTypeAffiliates_GetAll default %s", o._statusCode, payload)
}

func (o *ConstituentTypeAffiliatesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/ConstituentTypeAffiliates][%d] ConstituentTypeAffiliates_GetAll default %s", o._statusCode, payload)
}

func (o *ConstituentTypeAffiliatesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ConstituentTypeAffiliatesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
