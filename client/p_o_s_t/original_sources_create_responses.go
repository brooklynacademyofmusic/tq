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

// OriginalSourcesCreateReader is a Reader for the OriginalSourcesCreate structure.
type OriginalSourcesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *OriginalSourcesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewOriginalSourcesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /ReferenceData/OriginalSources] OriginalSources_Create", response, response.Code())
	}
}

// NewOriginalSourcesCreateOK creates a OriginalSourcesCreateOK with default headers values
func NewOriginalSourcesCreateOK() *OriginalSourcesCreateOK {
	return &OriginalSourcesCreateOK{}
}

/*
OriginalSourcesCreateOK describes a response with status code 200, with default header values.

OK
*/
type OriginalSourcesCreateOK struct {
	Payload *models.OriginalSource
}

// IsSuccess returns true when this original sources create o k response has a 2xx status code
func (o *OriginalSourcesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this original sources create o k response has a 3xx status code
func (o *OriginalSourcesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this original sources create o k response has a 4xx status code
func (o *OriginalSourcesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this original sources create o k response has a 5xx status code
func (o *OriginalSourcesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this original sources create o k response a status code equal to that given
func (o *OriginalSourcesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the original sources create o k response
func (o *OriginalSourcesCreateOK) Code() int {
	return 200
}

func (o *OriginalSourcesCreateOK) Error() string {
	return fmt.Sprintf("[POST /ReferenceData/OriginalSources][%d] originalSourcesCreateOK  %+v", 200, o.Payload)
}

func (o *OriginalSourcesCreateOK) String() string {
	return fmt.Sprintf("[POST /ReferenceData/OriginalSources][%d] originalSourcesCreateOK  %+v", 200, o.Payload)
}

func (o *OriginalSourcesCreateOK) GetPayload() *models.OriginalSource {
	return o.Payload
}

func (o *OriginalSourcesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OriginalSource)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}