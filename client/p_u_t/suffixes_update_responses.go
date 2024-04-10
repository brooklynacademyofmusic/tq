// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// SuffixesUpdateReader is a Reader for the SuffixesUpdate structure.
type SuffixesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SuffixesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSuffixesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[PUT /ReferenceData/Suffixes/{id}] Suffixes_Update", response, response.Code())
	}
}

// NewSuffixesUpdateOK creates a SuffixesUpdateOK with default headers values
func NewSuffixesUpdateOK() *SuffixesUpdateOK {
	return &SuffixesUpdateOK{}
}

/*
SuffixesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type SuffixesUpdateOK struct {
	Payload *models.Suffix
}

// IsSuccess returns true when this suffixes update o k response has a 2xx status code
func (o *SuffixesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this suffixes update o k response has a 3xx status code
func (o *SuffixesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this suffixes update o k response has a 4xx status code
func (o *SuffixesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this suffixes update o k response has a 5xx status code
func (o *SuffixesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this suffixes update o k response a status code equal to that given
func (o *SuffixesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the suffixes update o k response
func (o *SuffixesUpdateOK) Code() int {
	return 200
}

func (o *SuffixesUpdateOK) Error() string {
	return fmt.Sprintf("[PUT /ReferenceData/Suffixes/{id}][%d] suffixesUpdateOK  %+v", 200, o.Payload)
}

func (o *SuffixesUpdateOK) String() string {
	return fmt.Sprintf("[PUT /ReferenceData/Suffixes/{id}][%d] suffixesUpdateOK  %+v", 200, o.Payload)
}

func (o *SuffixesUpdateOK) GetPayload() *models.Suffix {
	return o.Payload
}

func (o *SuffixesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Suffix)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}