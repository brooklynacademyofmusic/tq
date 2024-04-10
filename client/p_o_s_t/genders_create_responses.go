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

// GendersCreateReader is a Reader for the GendersCreate structure.
type GendersCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GendersCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGendersCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /ReferenceData/Genders] Genders_Create", response, response.Code())
	}
}

// NewGendersCreateOK creates a GendersCreateOK with default headers values
func NewGendersCreateOK() *GendersCreateOK {
	return &GendersCreateOK{}
}

/*
GendersCreateOK describes a response with status code 200, with default header values.

OK
*/
type GendersCreateOK struct {
	Payload *models.Gender
}

// IsSuccess returns true when this genders create o k response has a 2xx status code
func (o *GendersCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this genders create o k response has a 3xx status code
func (o *GendersCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this genders create o k response has a 4xx status code
func (o *GendersCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this genders create o k response has a 5xx status code
func (o *GendersCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this genders create o k response a status code equal to that given
func (o *GendersCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the genders create o k response
func (o *GendersCreateOK) Code() int {
	return 200
}

func (o *GendersCreateOK) Error() string {
	return fmt.Sprintf("[POST /ReferenceData/Genders][%d] gendersCreateOK  %+v", 200, o.Payload)
}

func (o *GendersCreateOK) String() string {
	return fmt.Sprintf("[POST /ReferenceData/Genders][%d] gendersCreateOK  %+v", 200, o.Payload)
}

func (o *GendersCreateOK) GetPayload() *models.Gender {
	return o.Payload
}

func (o *GendersCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Gender)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}