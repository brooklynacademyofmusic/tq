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

// ConstituentsSwapConstituentA1A2Reader is a Reader for the ConstituentsSwapConstituentA1A2 structure.
type ConstituentsSwapConstituentA1A2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ConstituentsSwapConstituentA1A2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewConstituentsSwapConstituentA1A2OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /CRM/Constituents/{constituentId}/Snapshot/SwapA1A2] Constituents_SwapConstituentA1A2", response, response.Code())
	}
}

// NewConstituentsSwapConstituentA1A2OK creates a ConstituentsSwapConstituentA1A2OK with default headers values
func NewConstituentsSwapConstituentA1A2OK() *ConstituentsSwapConstituentA1A2OK {
	return &ConstituentsSwapConstituentA1A2OK{}
}

/*
ConstituentsSwapConstituentA1A2OK describes a response with status code 200, with default header values.

OK
*/
type ConstituentsSwapConstituentA1A2OK struct {
	Payload *models.ConstituentSnapshot
}

// IsSuccess returns true when this constituents swap constituent a1 a2 o k response has a 2xx status code
func (o *ConstituentsSwapConstituentA1A2OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this constituents swap constituent a1 a2 o k response has a 3xx status code
func (o *ConstituentsSwapConstituentA1A2OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this constituents swap constituent a1 a2 o k response has a 4xx status code
func (o *ConstituentsSwapConstituentA1A2OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this constituents swap constituent a1 a2 o k response has a 5xx status code
func (o *ConstituentsSwapConstituentA1A2OK) IsServerError() bool {
	return false
}

// IsCode returns true when this constituents swap constituent a1 a2 o k response a status code equal to that given
func (o *ConstituentsSwapConstituentA1A2OK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the constituents swap constituent a1 a2 o k response
func (o *ConstituentsSwapConstituentA1A2OK) Code() int {
	return 200
}

func (o *ConstituentsSwapConstituentA1A2OK) Error() string {
	return fmt.Sprintf("[POST /CRM/Constituents/{constituentId}/Snapshot/SwapA1A2][%d] constituentsSwapConstituentA1A2OK  %+v", 200, o.Payload)
}

func (o *ConstituentsSwapConstituentA1A2OK) String() string {
	return fmt.Sprintf("[POST /CRM/Constituents/{constituentId}/Snapshot/SwapA1A2][%d] constituentsSwapConstituentA1A2OK  %+v", 200, o.Payload)
}

func (o *ConstituentsSwapConstituentA1A2OK) GetPayload() *models.ConstituentSnapshot {
	return o.Payload
}

func (o *ConstituentsSwapConstituentA1A2OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConstituentSnapshot)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}