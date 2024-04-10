// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// RankingsDeleteReader is a Reader for the RankingsDelete structure.
type RankingsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RankingsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewRankingsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[DELETE /CRM/Rankings/{rankingId}] Rankings_Delete", response, response.Code())
	}
}

// NewRankingsDeleteNoContent creates a RankingsDeleteNoContent with default headers values
func NewRankingsDeleteNoContent() *RankingsDeleteNoContent {
	return &RankingsDeleteNoContent{}
}

/*
RankingsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type RankingsDeleteNoContent struct {
}

// IsSuccess returns true when this rankings delete no content response has a 2xx status code
func (o *RankingsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this rankings delete no content response has a 3xx status code
func (o *RankingsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rankings delete no content response has a 4xx status code
func (o *RankingsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this rankings delete no content response has a 5xx status code
func (o *RankingsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this rankings delete no content response a status code equal to that given
func (o *RankingsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the rankings delete no content response
func (o *RankingsDeleteNoContent) Code() int {
	return 204
}

func (o *RankingsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /CRM/Rankings/{rankingId}][%d] rankingsDeleteNoContent ", 204)
}

func (o *RankingsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /CRM/Rankings/{rankingId}][%d] rankingsDeleteNoContent ", 204)
}

func (o *RankingsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}