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

// ResearchCreateReader is a Reader for the ResearchCreate structure.
type ResearchCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ResearchCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewResearchCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /CRM/Research] Research_Create", response, response.Code())
	}
}

// NewResearchCreateOK creates a ResearchCreateOK with default headers values
func NewResearchCreateOK() *ResearchCreateOK {
	return &ResearchCreateOK{}
}

/*
ResearchCreateOK describes a response with status code 200, with default header values.

OK
*/
type ResearchCreateOK struct {
	Payload *models.ResearchEntry
}

// IsSuccess returns true when this research create o k response has a 2xx status code
func (o *ResearchCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this research create o k response has a 3xx status code
func (o *ResearchCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this research create o k response has a 4xx status code
func (o *ResearchCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this research create o k response has a 5xx status code
func (o *ResearchCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this research create o k response a status code equal to that given
func (o *ResearchCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the research create o k response
func (o *ResearchCreateOK) Code() int {
	return 200
}

func (o *ResearchCreateOK) Error() string {
	return fmt.Sprintf("[POST /CRM/Research][%d] researchCreateOK  %+v", 200, o.Payload)
}

func (o *ResearchCreateOK) String() string {
	return fmt.Sprintf("[POST /CRM/Research][%d] researchCreateOK  %+v", 200, o.Payload)
}

func (o *ResearchCreateOK) GetPayload() *models.ResearchEntry {
	return o.Payload
}

func (o *ResearchCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResearchEntry)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}