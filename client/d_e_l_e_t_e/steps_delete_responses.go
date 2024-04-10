// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// StepsDeleteReader is a Reader for the StepsDelete structure.
type StepsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *StepsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewStepsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[DELETE /Finance/Steps/{stepId}] Steps_Delete", response, response.Code())
	}
}

// NewStepsDeleteNoContent creates a StepsDeleteNoContent with default headers values
func NewStepsDeleteNoContent() *StepsDeleteNoContent {
	return &StepsDeleteNoContent{}
}

/*
StepsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type StepsDeleteNoContent struct {
}

// IsSuccess returns true when this steps delete no content response has a 2xx status code
func (o *StepsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this steps delete no content response has a 3xx status code
func (o *StepsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this steps delete no content response has a 4xx status code
func (o *StepsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this steps delete no content response has a 5xx status code
func (o *StepsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this steps delete no content response a status code equal to that given
func (o *StepsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the steps delete no content response
func (o *StepsDeleteNoContent) Code() int {
	return 204
}

func (o *StepsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /Finance/Steps/{stepId}][%d] stepsDeleteNoContent ", 204)
}

func (o *StepsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /Finance/Steps/{stepId}][%d] stepsDeleteNoContent ", 204)
}

func (o *StepsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}