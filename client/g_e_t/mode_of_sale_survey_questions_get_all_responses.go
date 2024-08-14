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

// ModeOfSaleSurveyQuestionsGetAllReader is a Reader for the ModeOfSaleSurveyQuestionsGetAll structure.
type ModeOfSaleSurveyQuestionsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ModeOfSaleSurveyQuestionsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewModeOfSaleSurveyQuestionsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewModeOfSaleSurveyQuestionsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewModeOfSaleSurveyQuestionsGetAllOK creates a ModeOfSaleSurveyQuestionsGetAllOK with default headers values
func NewModeOfSaleSurveyQuestionsGetAllOK() *ModeOfSaleSurveyQuestionsGetAllOK {
	return &ModeOfSaleSurveyQuestionsGetAllOK{}
}

/*
ModeOfSaleSurveyQuestionsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type ModeOfSaleSurveyQuestionsGetAllOK struct {
	Payload []*models.ModeOfSaleSurveyQuestion
}

// IsSuccess returns true when this mode of sale survey questions get all o k response has a 2xx status code
func (o *ModeOfSaleSurveyQuestionsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this mode of sale survey questions get all o k response has a 3xx status code
func (o *ModeOfSaleSurveyQuestionsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this mode of sale survey questions get all o k response has a 4xx status code
func (o *ModeOfSaleSurveyQuestionsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this mode of sale survey questions get all o k response has a 5xx status code
func (o *ModeOfSaleSurveyQuestionsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this mode of sale survey questions get all o k response a status code equal to that given
func (o *ModeOfSaleSurveyQuestionsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the mode of sale survey questions get all o k response
func (o *ModeOfSaleSurveyQuestionsGetAllOK) Code() int {
	return 200
}

func (o *ModeOfSaleSurveyQuestionsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/ModeOfSaleSurveyQuestions][%d] modeOfSaleSurveyQuestionsGetAllOK %s", 200, payload)
}

func (o *ModeOfSaleSurveyQuestionsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/ModeOfSaleSurveyQuestions][%d] modeOfSaleSurveyQuestionsGetAllOK %s", 200, payload)
}

func (o *ModeOfSaleSurveyQuestionsGetAllOK) GetPayload() []*models.ModeOfSaleSurveyQuestion {
	return o.Payload
}

func (o *ModeOfSaleSurveyQuestionsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewModeOfSaleSurveyQuestionsGetAllDefault creates a ModeOfSaleSurveyQuestionsGetAllDefault with default headers values
func NewModeOfSaleSurveyQuestionsGetAllDefault(code int) *ModeOfSaleSurveyQuestionsGetAllDefault {
	return &ModeOfSaleSurveyQuestionsGetAllDefault{
		_statusCode: code,
	}
}

/*
ModeOfSaleSurveyQuestionsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type ModeOfSaleSurveyQuestionsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this mode of sale survey questions get all default response has a 2xx status code
func (o *ModeOfSaleSurveyQuestionsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this mode of sale survey questions get all default response has a 3xx status code
func (o *ModeOfSaleSurveyQuestionsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this mode of sale survey questions get all default response has a 4xx status code
func (o *ModeOfSaleSurveyQuestionsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this mode of sale survey questions get all default response has a 5xx status code
func (o *ModeOfSaleSurveyQuestionsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this mode of sale survey questions get all default response a status code equal to that given
func (o *ModeOfSaleSurveyQuestionsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the mode of sale survey questions get all default response
func (o *ModeOfSaleSurveyQuestionsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *ModeOfSaleSurveyQuestionsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/ModeOfSaleSurveyQuestions][%d] ModeOfSaleSurveyQuestions_GetAll default %s", o._statusCode, payload)
}

func (o *ModeOfSaleSurveyQuestionsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/ModeOfSaleSurveyQuestions][%d] ModeOfSaleSurveyQuestions_GetAll default %s", o._statusCode, payload)
}

func (o *ModeOfSaleSurveyQuestionsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ModeOfSaleSurveyQuestionsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}