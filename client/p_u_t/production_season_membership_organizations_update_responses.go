// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

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

// ProductionSeasonMembershipOrganizationsUpdateReader is a Reader for the ProductionSeasonMembershipOrganizationsUpdate structure.
type ProductionSeasonMembershipOrganizationsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ProductionSeasonMembershipOrganizationsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewProductionSeasonMembershipOrganizationsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewProductionSeasonMembershipOrganizationsUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewProductionSeasonMembershipOrganizationsUpdateOK creates a ProductionSeasonMembershipOrganizationsUpdateOK with default headers values
func NewProductionSeasonMembershipOrganizationsUpdateOK() *ProductionSeasonMembershipOrganizationsUpdateOK {
	return &ProductionSeasonMembershipOrganizationsUpdateOK{}
}

/*
ProductionSeasonMembershipOrganizationsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type ProductionSeasonMembershipOrganizationsUpdateOK struct {
	Payload *models.ProductionSeasonMembershipOrganization
}

// IsSuccess returns true when this production season membership organizations update o k response has a 2xx status code
func (o *ProductionSeasonMembershipOrganizationsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this production season membership organizations update o k response has a 3xx status code
func (o *ProductionSeasonMembershipOrganizationsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this production season membership organizations update o k response has a 4xx status code
func (o *ProductionSeasonMembershipOrganizationsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this production season membership organizations update o k response has a 5xx status code
func (o *ProductionSeasonMembershipOrganizationsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this production season membership organizations update o k response a status code equal to that given
func (o *ProductionSeasonMembershipOrganizationsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the production season membership organizations update o k response
func (o *ProductionSeasonMembershipOrganizationsUpdateOK) Code() int {
	return 200
}

func (o *ProductionSeasonMembershipOrganizationsUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/ProductionSeasonMembershipOrganizations/{id}][%d] productionSeasonMembershipOrganizationsUpdateOK %s", 200, payload)
}

func (o *ProductionSeasonMembershipOrganizationsUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/ProductionSeasonMembershipOrganizations/{id}][%d] productionSeasonMembershipOrganizationsUpdateOK %s", 200, payload)
}

func (o *ProductionSeasonMembershipOrganizationsUpdateOK) GetPayload() *models.ProductionSeasonMembershipOrganization {
	return o.Payload
}

func (o *ProductionSeasonMembershipOrganizationsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ProductionSeasonMembershipOrganization)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewProductionSeasonMembershipOrganizationsUpdateDefault creates a ProductionSeasonMembershipOrganizationsUpdateDefault with default headers values
func NewProductionSeasonMembershipOrganizationsUpdateDefault(code int) *ProductionSeasonMembershipOrganizationsUpdateDefault {
	return &ProductionSeasonMembershipOrganizationsUpdateDefault{
		_statusCode: code,
	}
}

/*
ProductionSeasonMembershipOrganizationsUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type ProductionSeasonMembershipOrganizationsUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this production season membership organizations update default response has a 2xx status code
func (o *ProductionSeasonMembershipOrganizationsUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this production season membership organizations update default response has a 3xx status code
func (o *ProductionSeasonMembershipOrganizationsUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this production season membership organizations update default response has a 4xx status code
func (o *ProductionSeasonMembershipOrganizationsUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this production season membership organizations update default response has a 5xx status code
func (o *ProductionSeasonMembershipOrganizationsUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this production season membership organizations update default response a status code equal to that given
func (o *ProductionSeasonMembershipOrganizationsUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the production season membership organizations update default response
func (o *ProductionSeasonMembershipOrganizationsUpdateDefault) Code() int {
	return o._statusCode
}

func (o *ProductionSeasonMembershipOrganizationsUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/ProductionSeasonMembershipOrganizations/{id}][%d] ProductionSeasonMembershipOrganizations_Update default %s", o._statusCode, payload)
}

func (o *ProductionSeasonMembershipOrganizationsUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /TXN/ProductionSeasonMembershipOrganizations/{id}][%d] ProductionSeasonMembershipOrganizations_Update default %s", o._statusCode, payload)
}

func (o *ProductionSeasonMembershipOrganizationsUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ProductionSeasonMembershipOrganizationsUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
