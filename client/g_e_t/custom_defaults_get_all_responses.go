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

// CustomDefaultsGetAllReader is a Reader for the CustomDefaultsGetAll structure.
type CustomDefaultsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CustomDefaultsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCustomDefaultsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCustomDefaultsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCustomDefaultsGetAllOK creates a CustomDefaultsGetAllOK with default headers values
func NewCustomDefaultsGetAllOK() *CustomDefaultsGetAllOK {
	return &CustomDefaultsGetAllOK{}
}

/*
CustomDefaultsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type CustomDefaultsGetAllOK struct {
	Payload []*models.CustomDefault
}

// IsSuccess returns true when this custom defaults get all o k response has a 2xx status code
func (o *CustomDefaultsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this custom defaults get all o k response has a 3xx status code
func (o *CustomDefaultsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this custom defaults get all o k response has a 4xx status code
func (o *CustomDefaultsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this custom defaults get all o k response has a 5xx status code
func (o *CustomDefaultsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this custom defaults get all o k response a status code equal to that given
func (o *CustomDefaultsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the custom defaults get all o k response
func (o *CustomDefaultsGetAllOK) Code() int {
	return 200
}

func (o *CustomDefaultsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CustomDefaults][%d] customDefaultsGetAllOK %s", 200, payload)
}

func (o *CustomDefaultsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CustomDefaults][%d] customDefaultsGetAllOK %s", 200, payload)
}

func (o *CustomDefaultsGetAllOK) GetPayload() []*models.CustomDefault {
	return o.Payload
}

func (o *CustomDefaultsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCustomDefaultsGetAllDefault creates a CustomDefaultsGetAllDefault with default headers values
func NewCustomDefaultsGetAllDefault(code int) *CustomDefaultsGetAllDefault {
	return &CustomDefaultsGetAllDefault{
		_statusCode: code,
	}
}

/*
CustomDefaultsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type CustomDefaultsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this custom defaults get all default response has a 2xx status code
func (o *CustomDefaultsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this custom defaults get all default response has a 3xx status code
func (o *CustomDefaultsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this custom defaults get all default response has a 4xx status code
func (o *CustomDefaultsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this custom defaults get all default response has a 5xx status code
func (o *CustomDefaultsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this custom defaults get all default response a status code equal to that given
func (o *CustomDefaultsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the custom defaults get all default response
func (o *CustomDefaultsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *CustomDefaultsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CustomDefaults][%d] CustomDefaults_GetAll default %s", o._statusCode, payload)
}

func (o *CustomDefaultsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/CustomDefaults][%d] CustomDefaults_GetAll default %s", o._statusCode, payload)
}

func (o *CustomDefaultsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CustomDefaultsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}