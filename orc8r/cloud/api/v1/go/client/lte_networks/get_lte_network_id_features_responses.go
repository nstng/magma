// Code generated by go-swagger; DO NOT EDIT.

package lte_networks

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "magma/orc8r/cloud/api/v1/go/models"
)

// GetLTENetworkIDFeaturesReader is a Reader for the GetLTENetworkIDFeatures structure.
type GetLTENetworkIDFeaturesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetLTENetworkIDFeaturesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetLTENetworkIDFeaturesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewGetLTENetworkIDFeaturesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGetLTENetworkIDFeaturesOK creates a GetLTENetworkIDFeaturesOK with default headers values
func NewGetLTENetworkIDFeaturesOK() *GetLTENetworkIDFeaturesOK {
	return &GetLTENetworkIDFeaturesOK{}
}

/*GetLTENetworkIDFeaturesOK handles this case with default header values.

Feature flags of the network
*/
type GetLTENetworkIDFeaturesOK struct {
	Payload *models.NetworkFeatures
}

func (o *GetLTENetworkIDFeaturesOK) Error() string {
	return fmt.Sprintf("[GET /lte/{network_id}/features][%d] getLteNetworkIdFeaturesOK  %+v", 200, o.Payload)
}

func (o *GetLTENetworkIDFeaturesOK) GetPayload() *models.NetworkFeatures {
	return o.Payload
}

func (o *GetLTENetworkIDFeaturesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.NetworkFeatures)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLTENetworkIDFeaturesDefault creates a GetLTENetworkIDFeaturesDefault with default headers values
func NewGetLTENetworkIDFeaturesDefault(code int) *GetLTENetworkIDFeaturesDefault {
	return &GetLTENetworkIDFeaturesDefault{
		_statusCode: code,
	}
}

/*GetLTENetworkIDFeaturesDefault handles this case with default header values.

Unexpected Error
*/
type GetLTENetworkIDFeaturesDefault struct {
	_statusCode int

	Payload *models.Error
}

// Code gets the status code for the get LTE network ID features default response
func (o *GetLTENetworkIDFeaturesDefault) Code() int {
	return o._statusCode
}

func (o *GetLTENetworkIDFeaturesDefault) Error() string {
	return fmt.Sprintf("[GET /lte/{network_id}/features][%d] GetLTENetworkIDFeatures default  %+v", o._statusCode, o.Payload)
}

func (o *GetLTENetworkIDFeaturesDefault) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetLTENetworkIDFeaturesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}