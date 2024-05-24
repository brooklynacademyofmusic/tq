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

// SectionsGetReader is a Reader for the SectionsGet structure.
type SectionsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SectionsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSectionsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSectionsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSectionsGetOK creates a SectionsGetOK with default headers values
func NewSectionsGetOK() *SectionsGetOK {
	return &SectionsGetOK{}
}

/*
SectionsGetOK describes a response with status code 200, with default header values.

OK
*/
type SectionsGetOK struct {
	Payload *models.Section
}

// IsSuccess returns true when this sections get o k response has a 2xx status code
func (o *SectionsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this sections get o k response has a 3xx status code
func (o *SectionsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this sections get o k response has a 4xx status code
func (o *SectionsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this sections get o k response has a 5xx status code
func (o *SectionsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this sections get o k response a status code equal to that given
func (o *SectionsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the sections get o k response
func (o *SectionsGetOK) Code() int {
	return 200
}

func (o *SectionsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Sections/{id}][%d] sectionsGetOK %s", 200, payload)
}

func (o *SectionsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Sections/{id}][%d] sectionsGetOK %s", 200, payload)
}

func (o *SectionsGetOK) GetPayload() *models.Section {
	return o.Payload
}

func (o *SectionsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Section)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSectionsGetDefault creates a SectionsGetDefault with default headers values
func NewSectionsGetDefault(code int) *SectionsGetDefault {
	return &SectionsGetDefault{
		_statusCode: code,
	}
}

/*
SectionsGetDefault describes a response with status code -1, with default header values.

Error
*/
type SectionsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this sections get default response has a 2xx status code
func (o *SectionsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this sections get default response has a 3xx status code
func (o *SectionsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this sections get default response has a 4xx status code
func (o *SectionsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this sections get default response has a 5xx status code
func (o *SectionsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this sections get default response a status code equal to that given
func (o *SectionsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the sections get default response
func (o *SectionsGetDefault) Code() int {
	return o._statusCode
}

func (o *SectionsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Sections/{id}][%d] Sections_Get default %s", o._statusCode, payload)
}

func (o *SectionsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Sections/{id}][%d] Sections_Get default %s", o._statusCode, payload)
}

func (o *SectionsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SectionsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
