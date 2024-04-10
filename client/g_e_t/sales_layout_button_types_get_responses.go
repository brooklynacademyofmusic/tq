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

// SalesLayoutButtonTypesGetReader is a Reader for the SalesLayoutButtonTypesGet structure.
type SalesLayoutButtonTypesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SalesLayoutButtonTypesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSalesLayoutButtonTypesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/SalesLayoutButtonTypes/{id}] SalesLayoutButtonTypes_Get", response, response.Code())
	}
}

// NewSalesLayoutButtonTypesGetOK creates a SalesLayoutButtonTypesGetOK with default headers values
func NewSalesLayoutButtonTypesGetOK() *SalesLayoutButtonTypesGetOK {
	return &SalesLayoutButtonTypesGetOK{}
}

/*
SalesLayoutButtonTypesGetOK describes a response with status code 200, with default header values.

OK
*/
type SalesLayoutButtonTypesGetOK struct {
	Payload *models.SalesLayoutButtonType
}

// IsSuccess returns true when this sales layout button types get o k response has a 2xx status code
func (o *SalesLayoutButtonTypesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this sales layout button types get o k response has a 3xx status code
func (o *SalesLayoutButtonTypesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this sales layout button types get o k response has a 4xx status code
func (o *SalesLayoutButtonTypesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this sales layout button types get o k response has a 5xx status code
func (o *SalesLayoutButtonTypesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this sales layout button types get o k response a status code equal to that given
func (o *SalesLayoutButtonTypesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the sales layout button types get o k response
func (o *SalesLayoutButtonTypesGetOK) Code() int {
	return 200
}

func (o *SalesLayoutButtonTypesGetOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/SalesLayoutButtonTypes/{id}][%d] salesLayoutButtonTypesGetOK  %+v", 200, o.Payload)
}

func (o *SalesLayoutButtonTypesGetOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/SalesLayoutButtonTypes/{id}][%d] salesLayoutButtonTypesGetOK  %+v", 200, o.Payload)
}

func (o *SalesLayoutButtonTypesGetOK) GetPayload() *models.SalesLayoutButtonType {
	return o.Payload
}

func (o *SalesLayoutButtonTypesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SalesLayoutButtonType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}