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

// PerformancePriceLayersSearchReader is a Reader for the PerformancePriceLayersSearch structure.
type PerformancePriceLayersSearchReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformancePriceLayersSearchReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPerformancePriceLayersSearchOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /TXN/PerformancePriceLayers/Search] PerformancePriceLayers_Search", response, response.Code())
	}
}

// NewPerformancePriceLayersSearchOK creates a PerformancePriceLayersSearchOK with default headers values
func NewPerformancePriceLayersSearchOK() *PerformancePriceLayersSearchOK {
	return &PerformancePriceLayersSearchOK{}
}

/*
PerformancePriceLayersSearchOK describes a response with status code 200, with default header values.

OK
*/
type PerformancePriceLayersSearchOK struct {
	Payload []*models.PerformancePriceLayer
}

// IsSuccess returns true when this performance price layers search o k response has a 2xx status code
func (o *PerformancePriceLayersSearchOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performance price layers search o k response has a 3xx status code
func (o *PerformancePriceLayersSearchOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performance price layers search o k response has a 4xx status code
func (o *PerformancePriceLayersSearchOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this performance price layers search o k response has a 5xx status code
func (o *PerformancePriceLayersSearchOK) IsServerError() bool {
	return false
}

// IsCode returns true when this performance price layers search o k response a status code equal to that given
func (o *PerformancePriceLayersSearchOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the performance price layers search o k response
func (o *PerformancePriceLayersSearchOK) Code() int {
	return 200
}

func (o *PerformancePriceLayersSearchOK) Error() string {
	return fmt.Sprintf("[POST /TXN/PerformancePriceLayers/Search][%d] performancePriceLayersSearchOK  %+v", 200, o.Payload)
}

func (o *PerformancePriceLayersSearchOK) String() string {
	return fmt.Sprintf("[POST /TXN/PerformancePriceLayers/Search][%d] performancePriceLayersSearchOK  %+v", 200, o.Payload)
}

func (o *PerformancePriceLayersSearchOK) GetPayload() []*models.PerformancePriceLayer {
	return o.Payload
}

func (o *PerformancePriceLayersSearchOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}