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

// ConstituentGroupsGetAllReader is a Reader for the ConstituentGroupsGetAll structure.
type ConstituentGroupsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ConstituentGroupsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewConstituentGroupsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/ConstituentGroups] ConstituentGroups_GetAll", response, response.Code())
	}
}

// NewConstituentGroupsGetAllOK creates a ConstituentGroupsGetAllOK with default headers values
func NewConstituentGroupsGetAllOK() *ConstituentGroupsGetAllOK {
	return &ConstituentGroupsGetAllOK{}
}

/*
ConstituentGroupsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type ConstituentGroupsGetAllOK struct {
	Payload []*models.ConstituentGroup
}

// IsSuccess returns true when this constituent groups get all o k response has a 2xx status code
func (o *ConstituentGroupsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this constituent groups get all o k response has a 3xx status code
func (o *ConstituentGroupsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this constituent groups get all o k response has a 4xx status code
func (o *ConstituentGroupsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this constituent groups get all o k response has a 5xx status code
func (o *ConstituentGroupsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this constituent groups get all o k response a status code equal to that given
func (o *ConstituentGroupsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the constituent groups get all o k response
func (o *ConstituentGroupsGetAllOK) Code() int {
	return 200
}

func (o *ConstituentGroupsGetAllOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/ConstituentGroups][%d] constituentGroupsGetAllOK  %+v", 200, o.Payload)
}

func (o *ConstituentGroupsGetAllOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/ConstituentGroups][%d] constituentGroupsGetAllOK  %+v", 200, o.Payload)
}

func (o *ConstituentGroupsGetAllOK) GetPayload() []*models.ConstituentGroup {
	return o.Payload
}

func (o *ConstituentGroupsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}