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

// QueryElementFiltersGetSummariesReader is a Reader for the QueryElementFiltersGetSummaries structure.
type QueryElementFiltersGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryElementFiltersGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQueryElementFiltersGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /Reporting/QueryElementFilters/Summary] QueryElementFilters_GetSummaries", response, response.Code())
	}
}

// NewQueryElementFiltersGetSummariesOK creates a QueryElementFiltersGetSummariesOK with default headers values
func NewQueryElementFiltersGetSummariesOK() *QueryElementFiltersGetSummariesOK {
	return &QueryElementFiltersGetSummariesOK{}
}

/*
QueryElementFiltersGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type QueryElementFiltersGetSummariesOK struct {
	Payload []*models.QueryElementFilterSummary
}

// IsSuccess returns true when this query element filters get summaries o k response has a 2xx status code
func (o *QueryElementFiltersGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query element filters get summaries o k response has a 3xx status code
func (o *QueryElementFiltersGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query element filters get summaries o k response has a 4xx status code
func (o *QueryElementFiltersGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this query element filters get summaries o k response has a 5xx status code
func (o *QueryElementFiltersGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this query element filters get summaries o k response a status code equal to that given
func (o *QueryElementFiltersGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the query element filters get summaries o k response
func (o *QueryElementFiltersGetSummariesOK) Code() int {
	return 200
}

func (o *QueryElementFiltersGetSummariesOK) Error() string {
	return fmt.Sprintf("[GET /Reporting/QueryElementFilters/Summary][%d] queryElementFiltersGetSummariesOK  %+v", 200, o.Payload)
}

func (o *QueryElementFiltersGetSummariesOK) String() string {
	return fmt.Sprintf("[GET /Reporting/QueryElementFilters/Summary][%d] queryElementFiltersGetSummariesOK  %+v", 200, o.Payload)
}

func (o *QueryElementFiltersGetSummariesOK) GetPayload() []*models.QueryElementFilterSummary {
	return o.Payload
}

func (o *QueryElementFiltersGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}