// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// QueryElementFiltersDeleteReader is a Reader for the QueryElementFiltersDelete structure.
type QueryElementFiltersDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QueryElementFiltersDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewQueryElementFiltersDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewQueryElementFiltersDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewQueryElementFiltersDeleteNoContent creates a QueryElementFiltersDeleteNoContent with default headers values
func NewQueryElementFiltersDeleteNoContent() *QueryElementFiltersDeleteNoContent {
	return &QueryElementFiltersDeleteNoContent{}
}

/*
QueryElementFiltersDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type QueryElementFiltersDeleteNoContent struct {
}

// IsSuccess returns true when this query element filters delete no content response has a 2xx status code
func (o *QueryElementFiltersDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this query element filters delete no content response has a 3xx status code
func (o *QueryElementFiltersDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this query element filters delete no content response has a 4xx status code
func (o *QueryElementFiltersDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this query element filters delete no content response has a 5xx status code
func (o *QueryElementFiltersDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this query element filters delete no content response a status code equal to that given
func (o *QueryElementFiltersDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the query element filters delete no content response
func (o *QueryElementFiltersDeleteNoContent) Code() int {
	return 204
}

func (o *QueryElementFiltersDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /Reporting/QueryElementFilters/{queryElementFilterId}][%d] queryElementFiltersDeleteNoContent", 204)
}

func (o *QueryElementFiltersDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /Reporting/QueryElementFilters/{queryElementFilterId}][%d] queryElementFiltersDeleteNoContent", 204)
}

func (o *QueryElementFiltersDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewQueryElementFiltersDeleteDefault creates a QueryElementFiltersDeleteDefault with default headers values
func NewQueryElementFiltersDeleteDefault(code int) *QueryElementFiltersDeleteDefault {
	return &QueryElementFiltersDeleteDefault{
		_statusCode: code,
	}
}

/*
QueryElementFiltersDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type QueryElementFiltersDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this query element filters delete default response has a 2xx status code
func (o *QueryElementFiltersDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this query element filters delete default response has a 3xx status code
func (o *QueryElementFiltersDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this query element filters delete default response has a 4xx status code
func (o *QueryElementFiltersDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this query element filters delete default response has a 5xx status code
func (o *QueryElementFiltersDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this query element filters delete default response a status code equal to that given
func (o *QueryElementFiltersDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the query element filters delete default response
func (o *QueryElementFiltersDeleteDefault) Code() int {
	return o._statusCode
}

func (o *QueryElementFiltersDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /Reporting/QueryElementFilters/{queryElementFilterId}][%d] QueryElementFilters_Delete default %s", o._statusCode, payload)
}

func (o *QueryElementFiltersDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /Reporting/QueryElementFilters/{queryElementFilterId}][%d] QueryElementFilters_Delete default %s", o._statusCode, payload)
}

func (o *QueryElementFiltersDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *QueryElementFiltersDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
