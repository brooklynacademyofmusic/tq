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

// InterestsGetAllReader is a Reader for the InterestsGetAll structure.
type InterestsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *InterestsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewInterestsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewInterestsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewInterestsGetAllOK creates a InterestsGetAllOK with default headers values
func NewInterestsGetAllOK() *InterestsGetAllOK {
	return &InterestsGetAllOK{}
}

/*
InterestsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type InterestsGetAllOK struct {
	Payload []*models.Interest
}

// IsSuccess returns true when this interests get all o k response has a 2xx status code
func (o *InterestsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this interests get all o k response has a 3xx status code
func (o *InterestsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this interests get all o k response has a 4xx status code
func (o *InterestsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this interests get all o k response has a 5xx status code
func (o *InterestsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this interests get all o k response a status code equal to that given
func (o *InterestsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the interests get all o k response
func (o *InterestsGetAllOK) Code() int {
	return 200
}

func (o *InterestsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Interests][%d] interestsGetAllOK %s", 200, payload)
}

func (o *InterestsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Interests][%d] interestsGetAllOK %s", 200, payload)
}

func (o *InterestsGetAllOK) GetPayload() []*models.Interest {
	return o.Payload
}

func (o *InterestsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewInterestsGetAllDefault creates a InterestsGetAllDefault with default headers values
func NewInterestsGetAllDefault(code int) *InterestsGetAllDefault {
	return &InterestsGetAllDefault{
		_statusCode: code,
	}
}

/*
InterestsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type InterestsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this interests get all default response has a 2xx status code
func (o *InterestsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this interests get all default response has a 3xx status code
func (o *InterestsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this interests get all default response has a 4xx status code
func (o *InterestsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this interests get all default response has a 5xx status code
func (o *InterestsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this interests get all default response a status code equal to that given
func (o *InterestsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the interests get all default response
func (o *InterestsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *InterestsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Interests][%d] Interests_GetAll default %s", o._statusCode, payload)
}

func (o *InterestsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Interests][%d] Interests_GetAll default %s", o._statusCode, payload)
}

func (o *InterestsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *InterestsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
