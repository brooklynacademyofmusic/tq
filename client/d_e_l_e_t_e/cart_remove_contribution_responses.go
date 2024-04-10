// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// CartRemoveContributionReader is a Reader for the CartRemoveContribution structure.
type CartRemoveContributionReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CartRemoveContributionReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewCartRemoveContributionNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[DELETE /Web/Cart/{sessionKey}/Contributions/{lineItemId}] Cart_RemoveContribution", response, response.Code())
	}
}

// NewCartRemoveContributionNoContent creates a CartRemoveContributionNoContent with default headers values
func NewCartRemoveContributionNoContent() *CartRemoveContributionNoContent {
	return &CartRemoveContributionNoContent{}
}

/*
CartRemoveContributionNoContent describes a response with status code 204, with default header values.

No Content
*/
type CartRemoveContributionNoContent struct {
}

// IsSuccess returns true when this cart remove contribution no content response has a 2xx status code
func (o *CartRemoveContributionNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cart remove contribution no content response has a 3xx status code
func (o *CartRemoveContributionNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cart remove contribution no content response has a 4xx status code
func (o *CartRemoveContributionNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this cart remove contribution no content response has a 5xx status code
func (o *CartRemoveContributionNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this cart remove contribution no content response a status code equal to that given
func (o *CartRemoveContributionNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the cart remove contribution no content response
func (o *CartRemoveContributionNoContent) Code() int {
	return 204
}

func (o *CartRemoveContributionNoContent) Error() string {
	return fmt.Sprintf("[DELETE /Web/Cart/{sessionKey}/Contributions/{lineItemId}][%d] cartRemoveContributionNoContent ", 204)
}

func (o *CartRemoveContributionNoContent) String() string {
	return fmt.Sprintf("[DELETE /Web/Cart/{sessionKey}/Contributions/{lineItemId}][%d] cartRemoveContributionNoContent ", 204)
}

func (o *CartRemoveContributionNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}