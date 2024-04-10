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

// MembershipsCalculateReader is a Reader for the MembershipsCalculate structure.
type MembershipsCalculateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *MembershipsCalculateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewMembershipsCalculateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /CRM/Memberships/Calculate] Memberships_Calculate", response, response.Code())
	}
}

// NewMembershipsCalculateOK creates a MembershipsCalculateOK with default headers values
func NewMembershipsCalculateOK() *MembershipsCalculateOK {
	return &MembershipsCalculateOK{}
}

/*
MembershipsCalculateOK describes a response with status code 200, with default header values.

OK
*/
type MembershipsCalculateOK struct {
	Payload *models.CalculateMembershipResponse
}

// IsSuccess returns true when this memberships calculate o k response has a 2xx status code
func (o *MembershipsCalculateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this memberships calculate o k response has a 3xx status code
func (o *MembershipsCalculateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this memberships calculate o k response has a 4xx status code
func (o *MembershipsCalculateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this memberships calculate o k response has a 5xx status code
func (o *MembershipsCalculateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this memberships calculate o k response a status code equal to that given
func (o *MembershipsCalculateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the memberships calculate o k response
func (o *MembershipsCalculateOK) Code() int {
	return 200
}

func (o *MembershipsCalculateOK) Error() string {
	return fmt.Sprintf("[POST /CRM/Memberships/Calculate][%d] membershipsCalculateOK  %+v", 200, o.Payload)
}

func (o *MembershipsCalculateOK) String() string {
	return fmt.Sprintf("[POST /CRM/Memberships/Calculate][%d] membershipsCalculateOK  %+v", 200, o.Payload)
}

func (o *MembershipsCalculateOK) GetPayload() *models.CalculateMembershipResponse {
	return o.Payload
}

func (o *MembershipsCalculateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CalculateMembershipResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}