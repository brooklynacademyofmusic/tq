// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

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

// ProductionSeasonsGetAllReader is a Reader for the ProductionSeasonsGetAll structure.
type ProductionSeasonsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ProductionSeasonsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewProductionSeasonsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewProductionSeasonsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewProductionSeasonsGetAllOK creates a ProductionSeasonsGetAllOK with default headers values
func NewProductionSeasonsGetAllOK() *ProductionSeasonsGetAllOK {
	return &ProductionSeasonsGetAllOK{}
}

/*
ProductionSeasonsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type ProductionSeasonsGetAllOK struct {
	Payload []*models.ProductionSeason
}

// IsSuccess returns true when this production seasons get all o k response has a 2xx status code
func (o *ProductionSeasonsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this production seasons get all o k response has a 3xx status code
func (o *ProductionSeasonsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this production seasons get all o k response has a 4xx status code
func (o *ProductionSeasonsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this production seasons get all o k response has a 5xx status code
func (o *ProductionSeasonsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this production seasons get all o k response a status code equal to that given
func (o *ProductionSeasonsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the production seasons get all o k response
func (o *ProductionSeasonsGetAllOK) Code() int {
	return 200
}

func (o *ProductionSeasonsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/ProductionSeasons][%d] productionSeasonsGetAllOK %s", 200, payload)
}

func (o *ProductionSeasonsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/ProductionSeasons][%d] productionSeasonsGetAllOK %s", 200, payload)
}

func (o *ProductionSeasonsGetAllOK) GetPayload() []*models.ProductionSeason {
	return o.Payload
}

func (o *ProductionSeasonsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewProductionSeasonsGetAllDefault creates a ProductionSeasonsGetAllDefault with default headers values
func NewProductionSeasonsGetAllDefault(code int) *ProductionSeasonsGetAllDefault {
	return &ProductionSeasonsGetAllDefault{
		_statusCode: code,
	}
}

/*
ProductionSeasonsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type ProductionSeasonsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this production seasons get all default response has a 2xx status code
func (o *ProductionSeasonsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this production seasons get all default response has a 3xx status code
func (o *ProductionSeasonsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this production seasons get all default response has a 4xx status code
func (o *ProductionSeasonsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this production seasons get all default response has a 5xx status code
func (o *ProductionSeasonsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this production seasons get all default response a status code equal to that given
func (o *ProductionSeasonsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the production seasons get all default response
func (o *ProductionSeasonsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *ProductionSeasonsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/ProductionSeasons][%d] ProductionSeasons_GetAll default %s", o._statusCode, payload)
}

func (o *ProductionSeasonsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/ProductionSeasons][%d] ProductionSeasons_GetAll default %s", o._statusCode, payload)
}

func (o *ProductionSeasonsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ProductionSeasonsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
