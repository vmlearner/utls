// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log"

	"github.com/vmlearner/utls/internal/helper"
	"golang.org/x/crypto/cryptobyte"
)

// Naming convention:
// Unsupported things are prefixed with "Fake"
// Things, supported by utls, but not crypto/tls' are prefixed with "utls"
// Supported things, that have changed their ID are prefixed with "Old"
// Supported but disabled things are prefixed with "Disabled". We will _enable_ them.

// TLS handshake message types.
const (
	utlsTypeEncryptedExtensions uint8 = 8 // implemention incomplete by crypto/tls
	// https://datatracker.ietf.org/doc/html/rfc8879#section-7.2
	utlsTypeCompressedCertificate uint8 = 25
)

// TLS
const (
	extensionNextProtoNeg uint16 = 13172 // not IANA assigned. Removed by crypto/tls since Nov 2019

	utlsExtensionPadding                uint16 = 21
	utlsExtensionCompressCertificate    uint16 = 27     // https://datatracker.ietf.org/doc/html/rfc8879#section-7.1
	utlsExtensionApplicationSettings    uint16 = 17513  // not IANA assigned
	utlsExtensionApplicationSettingsNew uint16 = 17613  // not IANA assigned
	utlsFakeExtensionCustom             uint16 = 1234   // not IANA assigned, for ALPS
	utlsExtensionECH                    uint16 = 0xfe0d // draft-ietf-tls-esni-17
	utlsExtensionECHOuterExtensions     uint16 = 0xfd00 // draft-ietf-tls-esni-17

	// extensions with 'fake' prefix break connection, if server echoes them back
	FakeExtensionEncryptThenMAC       uint16 = 22
	fakeExtensionEncryptThenMAC       uint16 = 22
	fakeExtensionTokenBinding         uint16 = 24
	fakeExtensionDelegatedCredentials uint16 = 34
	fakeExtensionPreSharedKey         uint16 = 41
	fakeExtensionCustom               uint16 = 1234
	fakeOldExtensionChannelID         uint16 = 30031 // not IANA assigned
	fakeExtensionChannelID            uint16 = 30032 // not IANA assigned
)

const (
	OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = uint16(0xcc13)
	OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc14)

	DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = uint16(0xc024)
	DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   = uint16(0xc028)
	DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256         = uint16(0x003d)

	FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc15) // we can try to craft these ciphersuites
	FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           = uint16(0x009e) // from existing pieces, if needed

	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA    = uint16(0x0033)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA    = uint16(0x0039)
	FAKE_TLS_RSA_WITH_RC4_128_MD5            = uint16(0x0004)
	FAKE_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = uint16(0x009f)
	FAKE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA    = uint16(0x0032)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = uint16(0x006b)
	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = uint16(0x0067)
	FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV   = uint16(0x00ff)

	// https://docs.microsoft.com/en-us/dotnet/api/system.net.security.tlsciphersuite?view=netcore-3.1
	FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = uint16(0xc008)
)

const (
	CurveSECP256R1 CurveID = 0x0017
	CurveSECP384R1 CurveID = 0x0018
	CurveSECP521R1 CurveID = 0x0019
	CurveX25519    CurveID = 0x001d

	FakeCurveFFDHE2048 CurveID = 0x0100
	FakeCurveFFDHE3072 CurveID = 0x0101
	FakeCurveFFDHE4096 CurveID = 0x0102
	FakeCurveFFDHE6144 CurveID = 0x0103
	FakeCurveFFDHE8192 CurveID = 0x0104
)

const (
	X25519Kyber768Draft00 CurveID = 0x6399

	FakeCurveX25519Kyber512Draft00    CurveID = 0xfe30
	FakeCurveX25519Kyber768Draft00Old CurveID = 0xfe31
	FakeCurveP256Kyber768Draft00      CurveID = 0xfe32

	X25519Kyber512Draft00    CurveID = FakeCurveX25519Kyber512Draft00
	X25519Kyber768Draft00Old CurveID = FakeCurveX25519Kyber768Draft00Old
	P256Kyber768Draft00      CurveID = FakeCurveP256Kyber768Draft00
)

// Other things
const (
	fakeRecordSizeLimit uint16 = 0x001c
)

// newest signatures
var (
	FakePKCS1WithSHA224 SignatureScheme = 0x0301
	FakeECDSAWithSHA224 SignatureScheme = 0x0303

	FakeSHA1WithDSA   SignatureScheme = 0x0202
	FakeSHA256WithDSA SignatureScheme = 0x0402

	// fakeEd25519 = SignatureAndHash{0x08, 0x07}
	// fakeEd448 = SignatureAndHash{0x08, 0x08}
)

// fake curves(groups)
var (
	FakeFFDHE2048 = uint16(0x0100)
	FakeFFDHE3072 = uint16(0x0101)
)

// https://tools.ietf.org/html/draft-ietf-tls-certificate-compression-04
type CertCompressionAlgo uint16

const (
	CertCompressionZlib   CertCompressionAlgo = 0x0001
	CertCompressionBrotli CertCompressionAlgo = 0x0002
	CertCompressionZstd   CertCompressionAlgo = 0x0003
)

const (
	PskModePlain uint8 = pskModePlain
	PskModeDHE   uint8 = pskModeDHE
)

type ClientHelloSpecFactory func() (ClientHelloSpec, error)

var EmptyClientHelloSpecFactory = func() (ClientHelloSpec, error) {
	return ClientHelloSpec{}, fmt.Errorf("please implement this method")
}

type ClientHelloID struct {
	Client string

	RandomExtensionOrder bool

	// Version specifies version of a mimicked clients (e.g. browsers).
	// Not used in randomized, custom handshake, and default Go.
	Version string

	// Seed is only used for randomized fingerprints to seed PRNG.
	// Must not be modified once set.
	Seed *PRNGSeed

	// Weights are only used for randomized fingerprints in func
	// generateRandomizedSpec(). Must not be modified once set.
	Weights *Weights

	SpecFactory ClientHelloSpecFactory
}

func (p *ClientHelloID) Str() string {
	return fmt.Sprintf("%s-%s", p.Client, p.Version)
}

func (p *ClientHelloID) IsSet() bool {
	return (p.Client == "") && (p.Version == "")
}

func (p *ClientHelloID) ToSpec() (ClientHelloSpec, error) {
	return p.SpecFactory()
}

const (
	// clients
	helloGolang           = "Golang"
	helloRandomized       = "Randomized"
	helloRandomizedALPN   = "Randomized-ALPN"
	helloRandomizedNoALPN = "Randomized-NoALPN"
	helloCustomInternal   = "CustomInternal"
	helloFirefox          = "Firefox"
	helloOpera            = "Opera"
	helloChrome           = "Chrome"
	helloIOS              = "iOS"
	helloIPad             = "iPad"
	helloSafari           = "Safari"
	helloAndroid          = "Android"
	helloEdge             = "Edge"
	hello360              = "360Browser"
	helloQQ               = "QQBrowser"

	// versions
	helloAutoVers = "0"
)

type ClientHelloSpec struct {
	CipherSuites       []uint16       // nil => default
	CompressionMethods []uint8        // nil => no compression
	Extensions         []TLSExtension // nil => no extensions

	TLSVersMin uint16 // [1.0-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.0
	TLSVersMax uint16 // [1.2-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.2

	// GreaseStyle: currently only random
	// sessionID may or may not depend on ticket; nil => random
	GetSessionID func(ticket []byte) [32]byte

	// TLSFingerprintLink string // ?? link to tlsfingerprint.io for informational purposes
}

// ReadCipherSuites is a helper function to construct a list of cipher suites from
// a []byte into []uint16.
//
// example: []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03} => []uint16{0x1301, 0x1302, 0x1303}
func (chs *ClientHelloSpec) ReadCipherSuites(b []byte) error {
	cipherSuites := []uint16{}
	s := cryptobyte.String(b)
	for !s.Empty() {
		var suite uint16
		if !s.ReadUint16(&suite) {
			return errors.New("unable to read ciphersuite")
		}
		cipherSuites = append(cipherSuites, unGREASEUint16(suite))
	}
	chs.CipherSuites = cipherSuites
	return nil
}

// ReadCompressionMethods is a helper function to construct a list of compression
// methods from a []byte into []uint8.
func (chs *ClientHelloSpec) ReadCompressionMethods(compressionMethods []byte) error {
	chs.CompressionMethods = compressionMethods
	return nil
}

// ReadTLSExtensions is a helper function to construct a list of TLS extensions from
// a byte slice into []TLSExtension.
func (chs *ClientHelloSpec) ReadTLSExtensions(b []byte, allowBluntMimicry bool, realPSK bool) error {
	extensions := cryptobyte.String(b)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) {
			return fmt.Errorf("unable to read extension ID")
		}
		if !extensions.ReadUint16LengthPrefixed(&extData) {
			return fmt.Errorf("unable to read data for extension %x", extension)
		}

		ext := ExtensionFromID(extension)
		extWriter, ok := ext.(TLSExtensionWriter)
		if ext != nil && ok { // known extension and implements TLSExtensionWriter properly
			switch extension {
			case ExtensionPreSharedKey:
				// PSK extension, need to see if we do real or fake PSK
				if realPSK {
					extWriter = &UtlsPreSharedKeyExtension{}
				} else {
					extWriter = &FakePreSharedKeyExtension{}
				}
			case ExtensionSupportedVersions:
				chs.TLSVersMin = 0
				chs.TLSVersMax = 0
			}

			if _, err := extWriter.Write(extData); err != nil {
				return err
			}

			chs.Extensions = append(chs.Extensions, extWriter)
		} else {
			if allowBluntMimicry {
				chs.Extensions = append(chs.Extensions, &GenericExtension{extension, extData})
			} else {
				return fmt.Errorf("unsupported extension %d", extension)
			}
		}
	}
	return nil
}

func (chs *ClientHelloSpec) AlwaysAddPadding() {
	alreadyHasPadding := false
	for idx, ext := range chs.Extensions {
		if _, ok := ext.(*UtlsPaddingExtension); ok {
			alreadyHasPadding = true
			break
		}
		if _, ok := ext.(PreSharedKeyExtension); ok {
			alreadyHasPadding = true // PSK must be last, so we can't append padding after it
			// instead we will insert padding before PSK
			chs.Extensions = append(chs.Extensions[:idx], append([]TLSExtension{&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}}, chs.Extensions[idx:]...)...)
			break
		}
	}
	if !alreadyHasPadding {
		chs.Extensions = append(chs.Extensions, &UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle})
	}
}

// Import TLS ClientHello data from client.tlsfingerprint.io:8443
//
// data is a map of []byte with following keys:
// - cipher_suites: [10, 10, 19, 1, 19, 2, 19, 3, 192, 43, 192, 47, 192, 44, 192, 48, 204, 169, 204, 168, 192, 19, 192, 20, 0, 156, 0, 157, 0, 47, 0, 53]
// - compression_methods: [0] => null
// - extensions: [10, 10, 255, 1, 0, 45, 0, 35, 0, 16, 68, 105, 0, 11, 0, 43, 0, 18, 0, 13, 0, 0, 0, 10, 0, 27, 0, 5, 0, 51, 0, 23, 10, 10, 0, 21]
// - pt_fmts (ec_point_formats): [1, 0] => len: 1, content: 0x00
// - sig_algs （signature_algorithms): [0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1] => len: 16, content: 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601
// - supported_versions: [10, 10, 3, 4, 3, 3] => 0x0a0a, 0x0304, 0x0303 (GREASE, TLS 1.3, TLS 1.2)
// - curves (named_groups, supported_groups): [0, 8, 10, 10, 0, 29, 0, 23, 0, 24] => len: 8, content: GREASE, 0x001d, 0x0017, 0x0018
// - alpn: [0, 12, 2, 104, 50, 8, 104, 116, 116, 112, 47, 49, 46, 49] => len: 12, content: h2, http/1.1
// - key_share: [10, 10, 0, 1, 0, 29, 0, 32] => {group: 0x0a0a, len:1}, {group: 0x001d, len:32}
// - psk_key_exchange_modes: [1] => psk_dhe_ke(0x01)
// - cert_compression_algs: [2, 0, 2] => brotli (0x0002)
// - record_size_limit: [0, 255] => 255
//
// TLSVersMin/TLSVersMax are set to 0 if supported_versions is present.
// To prevent conflict, they should be set manually if needed BEFORE calling this function.
func (chs *ClientHelloSpec) ImportTLSClientHello(data map[string][]byte) error {
	var tlsExtensionTypes []uint16
	var err error

	if data["cipher_suites"] == nil {
		return errors.New("cipher_suites is required")
	}
	chs.CipherSuites, err = helper.Uint8to16(data["cipher_suites"])
	if err != nil {
		return err
	}

	if data["compression_methods"] == nil {
		return errors.New("compression_methods is required")
	}
	chs.CompressionMethods = data["compression_methods"]

	if data["extensions"] == nil {
		return errors.New("extensions is required")
	}
	tlsExtensionTypes, err = helper.Uint8to16(data["extensions"])
	if err != nil {
		return err
	}

	for _, extType := range tlsExtensionTypes {
		extension := ExtensionFromID(extType)
		extWriter, ok := extension.(TLSExtensionWriter)
		if !ok {
			return fmt.Errorf("unsupported extension %d", extType)
		}
		if extension == nil || !ok {
			log.Printf("[Warning] Unsupported extension %d added as a &GenericExtension without Data", extType)
			chs.Extensions = append(chs.Extensions, &GenericExtension{extType, []byte{}})
		} else {
			switch extType {
			case ExtensionSupportedPoints:
				if data["pt_fmts"] == nil {
					return errors.New("pt_fmts is required")
				}
				_, err = extWriter.Write(data["pt_fmts"])
				if err != nil {
					return err
				}
			case ExtensionSignatureAlgorithms:
				if data["sig_algs"] == nil {
					return errors.New("sig_algs is required")
				}
				_, err = extWriter.Write(data["sig_algs"])
				if err != nil {
					return err
				}
			case ExtensionSupportedVersions:
				chs.TLSVersMin = 0
				chs.TLSVersMax = 0

				if data["supported_versions"] == nil {
					return errors.New("supported_versions is required")
				}

				// need to add uint8 length prefix
				fixedData := make([]byte, len(data["supported_versions"])+1)
				fixedData[0] = uint8(len(data["supported_versions"]) & 0xff)
				copy(fixedData[1:], data["supported_versions"])
				_, err = extWriter.Write(fixedData)
				if err != nil {
					return err
				}
			case ExtensionSupportedCurves:
				if data["curves"] == nil {
					return errors.New("curves is required")
				}

				_, err = extWriter.Write(data["curves"])
				if err != nil {
					return err
				}
			case ExtensionALPN:
				if data["alpn"] == nil {
					return errors.New("alpn is required")
				}

				_, err = extWriter.Write(data["alpn"])
				if err != nil {
					return err
				}
			case ExtensionKeyShare:
				if data["key_share"] == nil {
					return errors.New("key_share is required")
				}

				// need to add (zero) data per each key share, [10, 10, 0, 1] => [10, 10, 0, 1, 0]
				fixedData := make([]byte, 0)
				for i := 0; i < len(data["key_share"]); i += 4 {
					fixedData = append(fixedData, data["key_share"][i:i+4]...)
					for j := 0; j < int(data["key_share"][i+3]); j++ {
						fixedData = append(fixedData, 0)
					}
				}
				// add uint16 length prefix
				fixedData = append([]byte{uint8(len(fixedData) >> 8), uint8(len(fixedData) & 0xff)}, fixedData...)

				_, err = extWriter.Write(fixedData)
				if err != nil {
					return err
				}
			case ExtensionPSKModes:
				if data["psk_key_exchange_modes"] == nil {
					return errors.New("psk_key_exchange_modes is required")
				}

				// need to add uint8 length prefix
				fixedData := make([]byte, len(data["psk_key_exchange_modes"])+1)
				fixedData[0] = uint8(len(data["psk_key_exchange_modes"]) & 0xff)
				copy(fixedData[1:], data["psk_key_exchange_modes"])
				_, err = extWriter.Write(fixedData)
				if err != nil {
					return err
				}
			case utlsExtensionCompressCertificate:
				if data["cert_compression_algs"] == nil {
					return errors.New("cert_compression_algs is required")
				}

				// need to add uint8 length prefix
				fixedData := make([]byte, len(data["cert_compression_algs"])+1)
				fixedData[0] = uint8(len(data["cert_compression_algs"]) & 0xff)
				copy(fixedData[1:], data["cert_compression_algs"])
				_, err = extWriter.Write(fixedData)
				if err != nil {
					return err
				}
			case fakeRecordSizeLimit:
				if data["record_size_limit"] == nil {
					return errors.New("record_size_limit is required")
				}

				_, err = extWriter.Write(data["record_size_limit"]) // uint16 as []byte
				if err != nil {
					return err
				}
			case ExtensionALPSOld:
				// TODO: tlsfingerprint.io should record/provide application settings data
				ext := extWriter.(*ApplicationSettingsExtension)
				ext.SupportedProtocols = []string{"h2"}
			case ExtensionALPS:
				extWriter.(*ApplicationSettingsExtensionNew).SupportedProtocols = []string{"h2"}
			case ExtensionPreSharedKey:
				log.Printf("[Warning] PSK extension added without data")
			default:
				if !isGREASEUint16(extType) {
					log.Printf("[Warning] extension %d added without data", extType)
				} /*else {
					log.Printf("[Warning] GREASE extension added but ID/Data discarded. They will be automatically re-GREASEd on ApplyPreset() call.")
				}*/
			}
			chs.Extensions = append(chs.Extensions, extWriter)
		}
	}
	return nil
}

// ImportTLSClientHelloFromJSON imports ClientHelloSpec from JSON data from client.tlsfingerprint.io format
//
// It calls ImportTLSClientHello internally after unmarshaling JSON data into map[string][]byte
func (chs *ClientHelloSpec) ImportTLSClientHelloFromJSON(jsonB []byte) error {
	var data map[string][]byte
	err := json.Unmarshal(jsonB, &data)
	if err != nil {
		return err
	}
	return chs.ImportTLSClientHello(data)
}

// FromRaw converts a ClientHello message in the form of raw bytes into a ClientHelloSpec.
//
// ctrlFlags: []bool{bluntMimicry, realPSK}
func (chs *ClientHelloSpec) FromRaw(raw []byte, ctrlFlags ...bool) error {
	if chs == nil {
		return errors.New("cannot unmarshal into nil ClientHelloSpec")
	}

	var bluntMimicry = false
	var realPSK = false
	if len(ctrlFlags) > 0 {
		bluntMimicry = ctrlFlags[0]
	}
	if len(ctrlFlags) > 1 {
		realPSK = ctrlFlags[1]
	}

	*chs = ClientHelloSpec{} // reset
	s := cryptobyte.String(raw)

	var contentType uint8
	var recordVersion uint16
	if !s.ReadUint8(&contentType) || // record type
		!s.ReadUint16(&recordVersion) || !s.Skip(2) { // record version and length
		return errors.New("unable to read record type, version, and length")
	}

	if recordType(contentType) != recordTypeHandshake {
		return errors.New("record is not a handshake")
	}

	var handshakeVersion uint16
	var handshakeType uint8

	if !s.ReadUint8(&handshakeType) || !s.Skip(3) || // message type and 3 byte length
		!s.ReadUint16(&handshakeVersion) || !s.Skip(32) { // 32 byte random
		return errors.New("unable to read handshake message type, length, and random")
	}

	if handshakeType != typeClientHello {
		return errors.New("handshake message is not a ClientHello")
	}

	chs.TLSVersMin = recordVersion
	chs.TLSVersMax = handshakeVersion

	var ignoredSessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&ignoredSessionID) {
		return errors.New("unable to read session id")
	}

	// CipherSuites
	var cipherSuitesBytes cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuitesBytes) {
		return errors.New("unable to read ciphersuites")
	}

	if err := chs.ReadCipherSuites(cipherSuitesBytes); err != nil {
		return err
	}

	// CompressionMethods
	var compressionMethods cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&compressionMethods) {
		return errors.New("unable to read compression methods")
	}

	if err := chs.ReadCompressionMethods(compressionMethods); err != nil {
		return err
	}

	if s.Empty() {
		// Extensions are optional
		return nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return errors.New("unable to read extensions data")
	}

	if err := chs.ReadTLSExtensions(extensions, bluntMimicry, realPSK); err != nil {
		return err
	}

	// if extension list includes padding, we update the padding-to-len according to
	// the raw ClientHello length
	for _, ext := range chs.Extensions {
		if _, ok := ext.(*UtlsPaddingExtension); ok {
			ext.(*UtlsPaddingExtension).GetPaddingLen = AlwaysPadToLen(len(raw) - 5)
			break
		}
	}

	return nil
}

// UnmarshalJSON unmarshals a ClientHello message in the form of JSON into a ClientHelloSpec.
func (chs *ClientHelloSpec) UnmarshalJSON(jsonB []byte) error {
	var chsju ClientHelloSpecJSONUnmarshaler
	if err := json.Unmarshal(jsonB, &chsju); err != nil {
		return err
	}

	*chs = chsju.ClientHelloSpec()
	return nil
}

var (
	// HelloGolang will use default "crypto/tls" handshake marshaling codepath, which WILL
	// overwrite your changes to Hello(Config, Session are fine).
	// You might want to call BuildHandshakeState() before applying any changes.
	// UConn.Extensions will be completely ignored.
	HelloGolang = ClientHelloID{helloGolang, false, helloAutoVers, nil, nil, EmptyClientHelloSpecFactory}

	// HelloCustom will prepare ClientHello with empty uconn.Extensions so you can fill it with
	// TLSExtensions manually or use ApplyPreset function
	HelloCustom = ClientHelloID{helloCustomInternal, false, helloAutoVers, nil, nil, EmptyClientHelloSpecFactory}

	// HelloRandomized* randomly adds/reorders extensions, ciphersuites, etc.
	HelloRandomized       = ClientHelloID{helloRandomized, false, helloAutoVers, nil, nil, EmptyClientHelloSpecFactory}
	HelloRandomizedALPN   = ClientHelloID{helloRandomizedALPN, false, helloAutoVers, nil, nil, EmptyClientHelloSpecFactory}
	HelloRandomizedNoALPN = ClientHelloID{helloRandomizedNoALPN, false, helloAutoVers, nil, nil, EmptyClientHelloSpecFactory}

	// The rest will will parrot given browser.
	HelloFirefox_Auto = HelloFirefox_120
	HelloFirefox_55   = ClientHelloID{helloFirefox, false, "55", nil, nil, EmptyClientHelloSpecFactory}
	HelloFirefox_56   = ClientHelloID{helloFirefox, false, "56", nil, nil, EmptyClientHelloSpecFactory}
	HelloFirefox_63   = ClientHelloID{helloFirefox, false, "63", nil, nil, EmptyClientHelloSpecFactory}
	HelloFirefox_65   = ClientHelloID{helloFirefox, false, "65", nil, nil, EmptyClientHelloSpecFactory}
	HelloFirefox_99   = ClientHelloID{helloFirefox, false, "99", nil, nil, EmptyClientHelloSpecFactory}
	HelloFirefox_102  = ClientHelloID{helloFirefox, false, "102", nil, nil, EmptyClientHelloSpecFactory}
	HelloFirefox_104  = ClientHelloID{helloFirefox, false, "104", nil, nil, EmptyClientHelloSpecFactory}
	HelloFirefox_106  = ClientHelloID{helloFirefox, false, "106", nil, nil, EmptyClientHelloSpecFactory}
	HelloFirefox_108  = ClientHelloID{helloFirefox, false, "108", nil, nil, EmptyClientHelloSpecFactory}
	HelloFirefox_110  = ClientHelloID{helloFirefox, false, "110", nil, nil, EmptyClientHelloSpecFactory}
	HelloFirefox_105  = ClientHelloID{helloFirefox, false, "105", nil, nil, EmptyClientHelloSpecFactory}
	HelloFirefox_120  = ClientHelloID{helloFirefox, false, "120", nil, nil, EmptyClientHelloSpecFactory}

	HelloChrome_Auto        = HelloChrome_133
	HelloChrome_58          = ClientHelloID{helloChrome, false, "58", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_62          = ClientHelloID{helloChrome, false, "62", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_70          = ClientHelloID{helloChrome, false, "70", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_72          = ClientHelloID{helloChrome, false, "72", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_83          = ClientHelloID{helloChrome, false, "83", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_87          = ClientHelloID{helloChrome, false, "87", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_96          = ClientHelloID{helloChrome, false, "96", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_100         = ClientHelloID{helloChrome, false, "100", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_102         = ClientHelloID{helloChrome, false, "102", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_106_Shuffle = ClientHelloID{helloChrome, false, "106", nil, nil, EmptyClientHelloSpecFactory} // TLS Extension shuffler enabled starting from 106

	// Chrome w/ PSK: Chrome start sending this ClientHello after doing TLS 1.3 handshake with the same server.
	// Beta: PSK extension added. However, uTLS doesn't ship with full PSK support.
	// Use at your own discretion.
	HelloChrome_100_PSK         = ClientHelloID{helloChrome, false, "100_PSK", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_112_PSK         = ClientHelloID{helloChrome, false, "112_PSK", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_114_Padding_PSK = ClientHelloID{helloChrome, false, "114_PSK", nil, nil, EmptyClientHelloSpecFactory}

	// Chrome w/ Post-Quantum Key Agreement
	// Beta: PQ extension added. However, uTLS doesn't ship with full PQ support. Use at your own discretion.
	HelloChrome_115_PQ     = ClientHelloID{helloChrome, false, "115_PQ", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_115_PQ_PSK = ClientHelloID{helloChrome, false, "115_PQ_PSK", nil, nil, EmptyClientHelloSpecFactory}
	HelloOpera_Auto        = HelloOpera_91
	HelloOpera_91          = ClientHelloID{helloOpera, false, "91", nil, nil, EmptyClientHelloSpecFactory}
	HelloOpera_90          = ClientHelloID{helloOpera, false, "90", nil, nil, EmptyClientHelloSpecFactory}
	HelloOpera_89          = ClientHelloID{helloOpera, false, "89", nil, nil, EmptyClientHelloSpecFactory}

	HelloChrome_103 = ClientHelloID{helloChrome, false, "103", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_104 = ClientHelloID{helloChrome, false, "104", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_105 = ClientHelloID{helloChrome, false, "105", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_106 = ClientHelloID{helloChrome, false, "106", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_107 = ClientHelloID{helloChrome, false, "107", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_108 = ClientHelloID{helloChrome, false, "108", nil, nil, EmptyClientHelloSpecFactory}
	// Chrome ECH
	HelloChrome_120 = ClientHelloID{helloChrome, false, "120", nil, nil, EmptyClientHelloSpecFactory}
	// Chrome w/ Post-Quantum Key Agreement and Encrypted ClientHello
	HelloChrome_120_PQ = ClientHelloID{helloChrome, false, "120_PQ", nil, nil, EmptyClientHelloSpecFactory}

	// Chrome w/ ML-KEM curve
	HelloChrome_131 = ClientHelloID{helloChrome, false, "131", nil, nil, EmptyClientHelloSpecFactory}
	// Chrome w/ New ALPS codepoint
	HelloChrome_133 = ClientHelloID{helloChrome, false, "133", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_109 = ClientHelloID{helloChrome, false, "109", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_110 = ClientHelloID{helloChrome, false, "110", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_111 = ClientHelloID{helloChrome, false, "111", nil, nil, EmptyClientHelloSpecFactory}
	HelloChrome_112 = ClientHelloID{helloChrome, false, "112", nil, nil, EmptyClientHelloSpecFactory}

	HelloIOS_Auto = HelloIOS_16_0
	HelloIOS_11_1 = ClientHelloID{helloIOS, false, "111", nil, nil, EmptyClientHelloSpecFactory} // legacy "111" means 11.1
	HelloIOS_12_1 = ClientHelloID{helloIOS, false, "12.1", nil, nil, EmptyClientHelloSpecFactory}
	HelloIOS_13   = ClientHelloID{helloIOS, false, "13", nil, nil, EmptyClientHelloSpecFactory}
	HelloIOS_14   = ClientHelloID{helloIOS, false, "14", nil, nil, EmptyClientHelloSpecFactory}
	HelloIOS_15_5 = ClientHelloID{helloIOS, false, "15.5", nil, nil, EmptyClientHelloSpecFactory}
	HelloIOS_15_6 = ClientHelloID{helloIOS, false, "15.6", nil, nil, EmptyClientHelloSpecFactory}
	HelloIOS_16_0 = ClientHelloID{helloIOS, false, "16.0", nil, nil, EmptyClientHelloSpecFactory}

	HelloIPad_Auto = HelloIPad_15_6
	HelloIPad_15_6 = ClientHelloID{helloIPad, false, "15.6", nil, nil, EmptyClientHelloSpecFactory}

	HelloSafari_Auto   = HelloSafari_16_0
	HelloSafari_15_6_1 = ClientHelloID{helloSafari, false, "15.6.1", nil, nil, EmptyClientHelloSpecFactory}
	HelloSafari_16_0   = ClientHelloID{helloSafari, false, "16.0", nil, nil, EmptyClientHelloSpecFactory}

	HelloAndroid_11_OkHttp = ClientHelloID{helloAndroid, false, "11", nil, nil, EmptyClientHelloSpecFactory}

	HelloEdge_Auto = HelloEdge_85 // HelloEdge_106 seems to be incompatible with this library
	HelloEdge_85   = ClientHelloID{helloEdge, false, "85", nil, nil, EmptyClientHelloSpecFactory}
	HelloEdge_106  = ClientHelloID{helloEdge, false, "106", nil, nil, EmptyClientHelloSpecFactory}

	Hello360_Auto = Hello360_7_5 // Hello360_11_0 seems to be incompatible with this library
	Hello360_7_5  = ClientHelloID{hello360, false, "7.5", nil, nil, EmptyClientHelloSpecFactory}
	Hello360_11_0 = ClientHelloID{hello360, false, "11.0", nil, nil, EmptyClientHelloSpecFactory}

	HelloQQ_Auto = HelloQQ_11_1
	HelloQQ_11_1 = ClientHelloID{helloQQ, false, "11.1", nil, nil, EmptyClientHelloSpecFactory}
)

type Weights struct {
	Extensions_Append_ALPN                             float64
	TLSVersMax_Set_VersionTLS13                        float64
	CipherSuites_Remove_RandomCiphers                  float64
	SigAndHashAlgos_Append_ECDSAWithSHA1               float64
	SigAndHashAlgos_Append_ECDSAWithP521AndSHA512      float64
	SigAndHashAlgos_Append_PSSWithSHA256               float64
	SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512 float64
	CurveIDs_Append_X25519                             float64
	CurveIDs_Append_CurveP521                          float64
	Extensions_Append_Padding                          float64
	Extensions_Append_Status                           float64
	Extensions_Append_SCT                              float64
	Extensions_Append_Reneg                            float64
	Extensions_Append_EMS                              float64
	FirstKeyShare_Set_CurveP256                        float64
	Extensions_Append_ALPS_Old                         float64
	Extensions_Append_ALPS                             float64
}

// Do not modify them directly as they may being used. If you
// want to use your custom weights, please make a copy first.
var DefaultWeights = Weights{
	Extensions_Append_ALPN:                             0.7,
	TLSVersMax_Set_VersionTLS13:                        0.4,
	CipherSuites_Remove_RandomCiphers:                  0.4,
	SigAndHashAlgos_Append_ECDSAWithSHA1:               0.63,
	SigAndHashAlgos_Append_ECDSAWithP521AndSHA512:      0.59,
	SigAndHashAlgos_Append_PSSWithSHA256:               0.51,
	SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512: 0.9,
	CurveIDs_Append_X25519:                             0.71,
	CurveIDs_Append_CurveP521:                          0.46,
	Extensions_Append_Padding:                          0.62,
	Extensions_Append_Status:                           0.74,
	Extensions_Append_SCT:                              0.46,
	Extensions_Append_Reneg:                            0.75,
	Extensions_Append_EMS:                              0.77,
	FirstKeyShare_Set_CurveP256:                        0.25,
	Extensions_Append_ALPS_Old:                         0.33,
	Extensions_Append_ALPS:                             0.33,
}

// based on spec's GreaseStyle, GREASE_PLACEHOLDER may be replaced by another GREASE value
// https://tools.ietf.org/html/draft-ietf-tls-grease-01
const GREASE_PLACEHOLDER = 0x0a0a

func isGREASEUint16(v uint16) bool {
	// First byte is same as second byte
	// and lowest nibble is 0xa
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}

func unGREASEUint16(v uint16) uint16 {
	if isGREASEUint16(v) {
		return GREASE_PLACEHOLDER
	} else {
		return v
	}
}

// utlsMacSHA384 returns a SHA-384 based MAC. These are only supported in TLS 1.2
// so the given version is ignored.
func utlsMacSHA384(key []byte) hash.Hash {
	return hmac.New(sha512.New384, key)
}

var utlsSupportedCipherSuites []*cipherSuite
var utlsSupportedGroups = []CurveID{
	X25519,
	CurveP256,
	CurveP384,
	CurveP521,
	// FAKEFFDHE2048,
	// FAKEFFDHE3072,
}

func isGroupSupported(id CurveID) bool {
	for _, group := range utlsSupportedGroups {
		if group == id {
			return true
		}
	}

	return false
}

func init() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheRSAKA,
			suiteECDHE | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
		{OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheECDSAKA,
			suiteECDHE | suiteECSign | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
	}...)
}

// EnableWeakCiphers allows utls connections to continue in some cases, when weak cipher was chosen.
// This provides better compatibility with servers on the web, but weakens security. Feel free
// to use this option if you establish additional secure connection inside of utls connection.
// This option does not change the shape of parrots (i.e. same ciphers will be offered either way).
// Must be called before establishing any connections.
func EnableWeakCiphers() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, rsaKA,
			suiteTLS12, cipherAES, macSHA256, nil},

		{DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheECDSAKA,
			suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
		{DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheRSAKA,
			suiteECDHE | suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
	}...)
}

func mapSlice[T any, U any](slice []T, transform func(T) U) []U {
	newSlice := make([]U, 0, len(slice))
	for _, t := range slice {
		newSlice = append(newSlice, transform(t))
	}
	return newSlice
}

func panicOnNil(caller string, params ...any) {
	for i, p := range params {
		if p == nil {
			panic(fmt.Sprintf("tls: %s failed: the [%d] parameter is nil", caller, i))
		}
	}
}

func anyTrue[T any](slice []T, predicate func(i int, t *T) bool) bool {
	for i := 0; i < len(slice); i++ {
		if predicate(i, &slice[i]) {
			return true
		}
	}
	return false
}

func allTrue[T any](slice []T, predicate func(i int, t *T) bool) bool {
	for i := 0; i < len(slice); i++ {
		if !predicate(i, &slice[i]) {
			return false
		}
	}
	return true
}

func uAssert(condition bool, msg string) {
	if !condition {
		panic(msg)
	}
}

func sliceEq[T comparable](sliceA []T, sliceB []T) bool {
	if len(sliceA) != len(sliceB) {
		return false
	}
	for i := 0; i < len(sliceA); i++ {
		if sliceA[i] != sliceB[i] {
			return false
		}
	}
	return true
}

type Initializable interface {
	// IsInitialized returns a boolean indicating whether the extension has been initialized.
	// If false is returned, utls will initialize the extension.
	IsInitialized() bool
}
