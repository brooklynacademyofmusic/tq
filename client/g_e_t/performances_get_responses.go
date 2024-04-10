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

// PerformancesGetReader is a Reader for the PerformancesGet structure.
type PerformancesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformancesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPerformancesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /TXN/Performances/{performanceId}] Performances_Get", response, response.Code())
	}
}

// NewPerformancesGetOK creates a PerformancesGetOK with default headers values
func NewPerformancesGetOK() *PerformancesGetOK {
	return &PerformancesGetOK{}
}

/*
PerformancesGetOK describes a response with status code 200, with default header values.

OK
*/
type PerformancesGetOK struct {
	Payload *models.Performance
}

// IsSuccess returns true when this performances get o k response has a 2xx status code
func (o *PerformancesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performances get o k response has a 3xx status code
func (o *PerformancesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performances get o k response has a 4xx status code
func (o *PerformancesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this performances get o k response has a 5xx status code
func (o *PerformancesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this performances get o k response a status code equal to that given
func (o *PerformancesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the performances get o k response
func (o *PerformancesGetOK) Code() int {
	return 200
}

func (o *PerformancesGetOK) Error() string {
	return fmt.Sprintf("[GET /TXN/Performances/{performanceId}][%d] performancesGetOK  %+v", 200, o.Payload)
}

func (o *PerformancesGetOK) String() string {
	return fmt.Sprintf("[GET /TXN/Performances/{performanceId}][%d] performancesGetOK  %+v", 200, o.Payload)
}

func (o *PerformancesGetOK) GetPayload() *models.Performance {
	return o.Payload
}

func (o *PerformancesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Performance)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}