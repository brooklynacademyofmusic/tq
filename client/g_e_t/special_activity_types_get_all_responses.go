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

// SpecialActivityTypesGetAllReader is a Reader for the SpecialActivityTypesGetAll structure.
type SpecialActivityTypesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SpecialActivityTypesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSpecialActivityTypesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/SpecialActivityTypes] SpecialActivityTypes_GetAll", response, response.Code())
	}
}

// NewSpecialActivityTypesGetAllOK creates a SpecialActivityTypesGetAllOK with default headers values
func NewSpecialActivityTypesGetAllOK() *SpecialActivityTypesGetAllOK {
	return &SpecialActivityTypesGetAllOK{}
}

/*
SpecialActivityTypesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type SpecialActivityTypesGetAllOK struct {
	Payload []*models.SpecialActivityType
}

// IsSuccess returns true when this special activity types get all o k response has a 2xx status code
func (o *SpecialActivityTypesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this special activity types get all o k response has a 3xx status code
func (o *SpecialActivityTypesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this special activity types get all o k response has a 4xx status code
func (o *SpecialActivityTypesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this special activity types get all o k response has a 5xx status code
func (o *SpecialActivityTypesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this special activity types get all o k response a status code equal to that given
func (o *SpecialActivityTypesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the special activity types get all o k response
func (o *SpecialActivityTypesGetAllOK) Code() int {
	return 200
}

func (o *SpecialActivityTypesGetAllOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/SpecialActivityTypes][%d] specialActivityTypesGetAllOK  %+v", 200, o.Payload)
}

func (o *SpecialActivityTypesGetAllOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/SpecialActivityTypes][%d] specialActivityTypesGetAllOK  %+v", 200, o.Payload)
}

func (o *SpecialActivityTypesGetAllOK) GetPayload() []*models.SpecialActivityType {
	return o.Payload
}

func (o *SpecialActivityTypesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}