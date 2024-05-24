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

// MachineSettingsUpdateReader is a Reader for the MachineSettingsUpdate structure.
type MachineSettingsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *MachineSettingsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewMachineSettingsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewMachineSettingsUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewMachineSettingsUpdateOK creates a MachineSettingsUpdateOK with default headers values
func NewMachineSettingsUpdateOK() *MachineSettingsUpdateOK {
	return &MachineSettingsUpdateOK{}
}

/*
MachineSettingsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type MachineSettingsUpdateOK struct {
	Payload *models.MachineSetting
}

// IsSuccess returns true when this machine settings update o k response has a 2xx status code
func (o *MachineSettingsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this machine settings update o k response has a 3xx status code
func (o *MachineSettingsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this machine settings update o k response has a 4xx status code
func (o *MachineSettingsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this machine settings update o k response has a 5xx status code
func (o *MachineSettingsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this machine settings update o k response a status code equal to that given
func (o *MachineSettingsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the machine settings update o k response
func (o *MachineSettingsUpdateOK) Code() int {
	return 200
}

func (o *MachineSettingsUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/MachineSettings/{id}][%d] machineSettingsUpdateOK %s", 200, payload)
}

func (o *MachineSettingsUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/MachineSettings/{id}][%d] machineSettingsUpdateOK %s", 200, payload)
}

func (o *MachineSettingsUpdateOK) GetPayload() *models.MachineSetting {
	return o.Payload
}

func (o *MachineSettingsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MachineSetting)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewMachineSettingsUpdateDefault creates a MachineSettingsUpdateDefault with default headers values
func NewMachineSettingsUpdateDefault(code int) *MachineSettingsUpdateDefault {
	return &MachineSettingsUpdateDefault{
		_statusCode: code,
	}
}

/*
MachineSettingsUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type MachineSettingsUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this machine settings update default response has a 2xx status code
func (o *MachineSettingsUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this machine settings update default response has a 3xx status code
func (o *MachineSettingsUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this machine settings update default response has a 4xx status code
func (o *MachineSettingsUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this machine settings update default response has a 5xx status code
func (o *MachineSettingsUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this machine settings update default response a status code equal to that given
func (o *MachineSettingsUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the machine settings update default response
func (o *MachineSettingsUpdateDefault) Code() int {
	return o._statusCode
}

func (o *MachineSettingsUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/MachineSettings/{id}][%d] MachineSettings_Update default %s", o._statusCode, payload)
}

func (o *MachineSettingsUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/MachineSettings/{id}][%d] MachineSettings_Update default %s", o._statusCode, payload)
}

func (o *MachineSettingsUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *MachineSettingsUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
