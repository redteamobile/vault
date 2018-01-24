package pki

import (
	"fmt"

	"crypto/x509"
	"github.com/hashicorp/vault/helper/certutil"
	"github.com/hashicorp/vault/helper/errutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConfigCA(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/ca",
		Fields: map[string]*framework.FieldSchema{
			"pem_bundle": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `PEM-format, concatenated unencrypted
secret key and certificate.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathCertWrite,
		},

		HelpSynopsis:    pathConfigCAHelpSyn,
		HelpDescription: pathConfigCAHelpDesc,
	}
}

func (b *backend) pathCertWrite(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	pemBundle := data.Get("pem_bundle").(string)

	parsedBundle, err := certutil.ParsePEMBundle(pemBundle)
	if err != nil {
		switch err.(type) {
		case errutil.InternalError:
			return nil, err
		default:
			return logical.ErrorResponse(err.Error()), nil
		}
	}

	/*
		if parsedBundle.PrivateKey == nil ||
			    parsedBundle.PrivateKeyType == certutil.UnknownPrivateKey {
		    return logical.ErrorResponse("private key not found in the PEM bundle"), nil
		}
	*/

	if parsedBundle.Certificate == nil {
		return logical.ErrorResponse("no certificate found in the PEM bundle"), nil
	}

	/*
		if !parsedBundle.Certificate.IsCA {
			return logical.ErrorResponse("the given certificate is not marked for CA use and cannot be used with this backend"), nil
		}
	*/

	cb, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, fmt.Errorf("error converting raw values into cert bundle: %s", err)
	}

	if parsedBundle.Certificate.IsCA {
		entry, err := logical.StorageEntryJSON("config/ca_bundle", cb)
		if err != nil {
			return nil, err
		}
		err = req.Storage.Put(entry)
		if err != nil {
			return nil, err
		}

		// For ease of later use, also store just the certificate at a known
		// location, plus a fresh CRL
		entry.Key = "ca"
		entry.Value = parsedBundle.CertificateBytes
		err = req.Storage.Put(entry)
		if err != nil {
			return nil, err
		}
	} else {

		currentCert := parsedBundle.Certificate

		certEntry, funcErr := fetchCertBySerial(req, "ca", "ca")
		if funcErr != nil {
			return nil, funcErr
		}
		if certEntry == nil {
			return nil, fmt.Errorf("no ca certificate existed")
		}

		caCert, err := x509.ParseCertificate(certEntry.Value)
		if err != nil {
			return nil, fmt.Errorf("unable to parse ca certificate locally: %v", err)
		}

		err = currentCert.CheckSignatureFrom(caCert)
		if err != nil {
			return nil, fmt.Errorf("unable to verify the given certificate: %v", err)
		}

		err = req.Storage.Put(&logical.StorageEntry{
			Key:   "certs/" + normalizeSerial(cb.SerialNumber),
			Value: parsedBundle.CertificateBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to store certificate locally: %v", err)
		}
	}

	if parsedBundle.PrivateKey != nil &&
		parsedBundle.PrivateKeyType != certutil.UnknownPrivateKey {
		err = buildCRL(b, req)
	}

	return nil, err
}

const pathConfigCAHelpSyn = `
Set the CA certificate and private key used for generated credentials.
`

const pathConfigCAHelpDesc = `
This sets the CA information used for credentials generated by this
by this mount. This must be a PEM-format, concatenated unencrypted
secret key and certificate.

For security reasons, the secret key cannot be retrieved later.
`

const pathConfigCAGenerateHelpSyn = `
Generate a new CA certificate and private key used for signing.
`

const pathConfigCAGenerateHelpDesc = `
This path generates a CA certificate and private key to be used for
credentials generated by this mount. The path can either
end in "internal" or "exported"; this controls whether the
unencrypted private key is exported after generation. This will
be your only chance to export the private key; for security reasons
it cannot be read or exported later.

If the "type" option is set to "self-signed", the generated
certificate will be a self-signed root CA. Otherwise, this mount
will act as an intermediate CA; a CSR will be returned, to be signed
by your chosen CA (which could be another mount of this backend).
Note that the CRL path will be set to this mount's CRL path; if you
need further customization it is recommended that you create a CSR
separately and get it signed. Either way, use the "config/ca/set"
endpoint to load the signed certificate into Vault.
`

const pathConfigCASignHelpSyn = `
Generate a signed CA certificate from a CSR.
`

const pathConfigCASignHelpDesc = `
This path generates a CA certificate to be used for credentials
generated by the certificate's destination mount.

Use the "config/ca/set" endpoint to load the signed certificate
into Vault another Vault mount.
`
