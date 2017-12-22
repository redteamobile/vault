package pki

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/helper/certutil"
	"github.com/hashicorp/vault/helper/errutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathEuiccIssue(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "euicc/" + framework.GenericNameRegex("role"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathEuiccIssue,
		},

		HelpSynopsis:    pathEuiccIssueHelpSyn,
		HelpDescription: pathEuiccIssueHelpDesc,
	}

	ret.Fields = addEuiccCommonFields(map[string]*framework.FieldSchema{})
	return ret
}

// pathIssue issues a certificate and private key from given parameters,
// subject to role restrictions
func (b *backend) pathEuiccIssue(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)

	// Get the role
	role, err := b.getRole(req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("Unknown role: %s", roleName)), nil
	}

	return b.pathIssueSignEuiccCert(req, data, role, false, false)
}

func (b *backend) pathIssueSignEuiccCert(
	req *logical.Request, data *framework.FieldData, role *roleEntry, useCSR, useCSRValues bool) (*logical.Response, error) {
	format := getFormat(data)
	if format == "" {
		return logical.ErrorResponse(
			`the "format" path parameter must be "pem", "der", or "pem_bundle"`), nil
	}

	var caErr error
	signingBundle, caErr := fetchCAInfo(req)
	switch caErr.(type) {
	case errutil.UserError:
		return nil, errutil.UserError{Err: fmt.Sprintf(
			"could not fetch the CA certificate (was one set?): %s", caErr)}
	case errutil.InternalError:
		return nil, errutil.InternalError{Err: fmt.Sprintf(
			"error fetching CA certificate: %s", caErr)}
	}

	var parsedBundle *certutil.ParsedCertBundle
	var err error
	if useCSR {
		err = errutil.UserError{Err: `signing CSR of eUICC certificate not supported yet`}
	} else {
		parsedBundle, err = generateEuiccCert(b, role, signingBundle, req, data)
	}
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		case errutil.InternalError:
			return nil, err
		}
	}

	signingCB, err := signingBundle.ToCertBundle()
	if err != nil {
		return nil, errwrap.Wrapf("error converting raw signing bundle to cert bundle: {{err}}", err)
	}

	cb, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, errwrap.Wrapf("error converting raw cert bundle to cert bundle: {{err}}", err)
	}

	respData := map[string]interface{}{
		"serial_number": cb.SerialNumber,
	}

	switch format {
	case "pem":
		respData["issuing_ca"] = signingCB.Certificate
		respData["certificate"] = cb.Certificate
		if cb.CAChain != nil && len(cb.CAChain) > 0 {
			respData["ca_chain"] = cb.CAChain
		}
		if !useCSR {
			respData["private_key"] = cb.PrivateKey
			respData["private_key_type"] = cb.PrivateKeyType
		}

	case "pem_bundle":
		respData["issuing_ca"] = signingCB.Certificate
		respData["certificate"] = cb.ToPEMBundle()
		if cb.CAChain != nil && len(cb.CAChain) > 0 {
			respData["ca_chain"] = cb.CAChain
		}
		if !useCSR {
			respData["private_key"] = cb.PrivateKey
			respData["private_key_type"] = cb.PrivateKeyType
		}

	case "der":
		respData["certificate"] = base64.StdEncoding.EncodeToString(parsedBundle.CertificateBytes)
		respData["issuing_ca"] = base64.StdEncoding.EncodeToString(signingBundle.CertificateBytes)

		var caChain []string
		for _, caCert := range parsedBundle.CAChain {
			caChain = append(caChain, base64.StdEncoding.EncodeToString(caCert.Bytes))
		}
		if caChain != nil && len(caChain) > 0 {
			respData["ca_chain"] = caChain
		}

		if !useCSR {
			respData["private_key"] = base64.StdEncoding.EncodeToString(parsedBundle.PrivateKeyBytes)
			respData["private_key_type"] = cb.PrivateKeyType
		}
	}

	var resp *logical.Response
	switch {
	case role.GenerateLease == nil:
		return nil, fmt.Errorf("generate lease in role is nil")
	case *role.GenerateLease == false:
		// If lease generation is disabled do not populate `Secret` field in
		// the response
		resp = &logical.Response{
			Data: respData,
		}
	default:
		resp = b.Secret(SecretCertsType).Response(
			respData,
			map[string]interface{}{
				"serial_number": cb.SerialNumber,
			})
		resp.Secret.TTL = parsedBundle.Certificate.NotAfter.Sub(time.Now())
	}

	if data.Get("private_key_format").(string) == "pkcs8" {
		err = convertRespToPKCS8(resp)
		if err != nil {
			return nil, err
		}
	}

	if !role.NoStore {
		err = req.Storage.Put(&logical.StorageEntry{
			Key:   "certs/" + normalizeSerial(cb.SerialNumber),
			Value: parsedBundle.CertificateBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to store certificate locally: %v", err)
		}
	}

	if useCSR {
		if role.UseCSRCommonName && data.Get("common_name").(string) != "" {
			resp.AddWarning("the common_name field was provided but the role is set with \"use_csr_common_name\" set to true")
		}
		if role.UseCSRSANs && data.Get("alt_names").(string) != "" {
			resp.AddWarning("the alt_names field was provided but the role is set with \"use_csr_sans\" set to true")
		}
	}

	return resp, nil
}

const pathEuiccIssueHelpSyn = `
Request a eUICC certificate using a certain role with the provided details.
`

const pathEuiccIssueHelpDesc = `
This path allows requesting a eUICC certificate to be issued according to the
policy of the given role. The eUICC certificate will only be issued if the
requested details are allowed by the role policy.

This path returns a eUICC certificate and a private key. If you want a workflow
that does not expose a private key, signing locally geenrate CSR is not supported 
yet.
`
