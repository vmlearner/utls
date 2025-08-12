// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// The marshalingFunction type is an adapter to allow the use of ordinary
// functions as cryptobyte.MarshalingValue.
type marshalingFunction func(b *cryptobyte.Builder) error

func (f marshalingFunction) Marshal(b *cryptobyte.Builder) error {
	return f(b)
}

// addBytesWithLength appends a sequence of bytes to the cryptobyte.Builder. If
// the length of the sequence is not the value specified, it produces an error.
func addBytesWithLength(b *cryptobyte.Builder, v []byte, n int) {
	b.AddValue(marshalingFunction(func(b *cryptobyte.Builder) error {
		if len(v) != n {
			return fmt.Errorf("invalid value length: expected %d, got %d", n, len(v))
		}
		b.AddBytes(v)
		return nil
	}))
}

// addUint64 appends a big-endian, 64-bit value to the cryptobyte.Builder.
func addUint64(b *cryptobyte.Builder, v uint64) {
	b.AddUint32(uint32(v >> 32))
	b.AddUint32(uint32(v))
}

// readUint64 decodes a big-endian, 64-bit value into out and advances over it.
// It reports whether the read was successful.
func readUint64(s *cryptobyte.String, out *uint64) bool {
	var hi, lo uint32
	if !s.ReadUint32(&hi) || !s.ReadUint32(&lo) {
		return false
	}
	*out = uint64(hi)<<32 | uint64(lo)
	return true
}

// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}

// readUint16LengthPrefixed acts like s.ReadUint16LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

// readUint24LengthPrefixed acts like s.ReadUint24LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint24LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint24LengthPrefixed((*cryptobyte.String)(out))
}

type clientHelloMsg struct {
	original                         []byte
	vers                             uint16
	random                           []byte
	sessionId                        []byte
	cipherSuites                     []uint16
	compressionMethods               []uint8
	serverName                       string
	ocspStapling                     bool
	supportedCurves                  []CurveID
	supportedPoints                  []uint8
	ticketSupported                  bool
	sessionTicket                    []uint8
	supportedSignatureAlgorithms     []SignatureScheme
	supportedSignatureAlgorithmsCert []SignatureScheme
	secureRenegotiationSupported     bool
	secureRenegotiation              []byte
	extendedMasterSecret             bool
	alpnProtocols                    []string
	scts                             bool
	// ems                              bool // [uTLS] actually implemented due to its prevalence // removed since crypto/tls implements it
	supportedVersions       []uint16
	cookie                  []byte
	keyShares               []keyShare
	earlyData               bool
	pskModes                []uint8
	pskIdentities           []pskIdentity
	pskBinders              [][]byte
	quicTransportParameters []byte
	encryptedClientHello    []byte
	// extensions are only populated on the server-side of a handshake
	extensions []uint16

	// [uTLS]
	nextProtoNeg bool
}

func (m *clientHelloMsg) marshalMsg(echInner bool) ([]byte, error) {
	// [uTLS SECTION BEGIN]
	return m.marshalMsgReorderOuterExts(echInner, nil)
}

func (m *clientHelloMsg) marshalMsgReorderOuterExts(echInner bool, outerExts []uint16) ([]byte, error) {
	// [uTLS SECTION END]
	var exts cryptobyte.Builder
	if m.nextProtoNeg {
		// draft-agl-tls-nextprotoneg-04
		exts.AddUint16(ExtensionNextProtoNeg)
		exts.AddUint16(0) // empty extension_data
	}
	if len(m.serverName) > 0 {
		// RFC 6066, Section 3
		exts.AddUint16(ExtensionServerName)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8(0) // name_type = host_name
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes([]byte(m.serverName))
				})
			})
		})
	}
	if len(m.supportedPoints) > 0 && !echInner {
		// RFC 4492, Section 5.1.2
		exts.AddUint16(ExtensionSupportedPoints)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.supportedPoints)
			})
		})
	}
	if m.ticketSupported && !echInner {
		// RFC 5077, Section 3.2
		exts.AddUint16(ExtensionSessionTicket)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddBytes(m.sessionTicket)
		})
	}
	if m.secureRenegotiationSupported && !echInner {
		// RFC 5746, Section 3.2
		exts.AddUint16(extensionRenegotiationInfo)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.secureRenegotiation)
			})
		})
	}
	if m.extendedMasterSecret && !echInner {
		// RFC 7627
		exts.AddUint16(ExtensionExtendedMasterSecret)
		exts.AddUint16(0) // empty extension_data
	}
	if m.scts {
		// RFC 6962, Section 3.3.1
		exts.AddUint16(ExtensionSCT)
		exts.AddUint16(0) // empty extension_data
	}
	if m.earlyData {
		// RFC 8446, Section 4.2.10
		exts.AddUint16(ExtensionEarlyData)
		exts.AddUint16(0) // empty extension_data
	}
	if m.quicTransportParameters != nil { // marshal zero-length parameters when present
		// RFC 9001, Section 8.2
		exts.AddUint16(ExtensionQUICTransportParameters)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddBytes(m.quicTransportParameters)
		})
	}
	if len(m.encryptedClientHello) > 0 {
		exts.AddUint16(extensionEncryptedClientHello)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddBytes(m.encryptedClientHello)
		})
	}
	// Note that any extension that can be compressed during ECH must be
	// contiguous. If any additional extensions are to be compressed they must
	// be added to the following block, so that they can be properly
	// decompressed on the other side.
	var echOuterExts []uint16
	if m.ocspStapling {
		// RFC 4366, Section 3.6
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionStatusRequest)
		} else {
			exts.AddUint16(ExtensionStatusRequest)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8(1)  // status_type = ocsp
				exts.AddUint16(0) // empty responder_id_list
				exts.AddUint16(0) // empty request_extensions
			})
		}
	}
	if len(m.supportedCurves) > 0 {
		// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionSupportedCurves)
		} else {
			exts.AddUint16(ExtensionSupportedCurves)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, curve := range m.supportedCurves {
						exts.AddUint16(uint16(curve))
					}
				})
			})
		}
	}
	if len(m.supportedSignatureAlgorithms) > 0 {
		// RFC 5246, Section 7.4.1.4.1
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionSignatureAlgorithms)
		} else {
			exts.AddUint16(ExtensionSignatureAlgorithms)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, sigAlgo := range m.supportedSignatureAlgorithms {
						exts.AddUint16(uint16(sigAlgo))
					}
				})
			})
		}
	}
	if len(m.supportedSignatureAlgorithmsCert) > 0 {
		// RFC 8446, Section 4.2.3
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionSignatureAlgorithmsCert)
		} else {
			exts.AddUint16(ExtensionSignatureAlgorithmsCert)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, sigAlgo := range m.supportedSignatureAlgorithmsCert {
						exts.AddUint16(uint16(sigAlgo))
					}
				})
			})
		}
	}
	if len(m.alpnProtocols) > 0 {
		// RFC 7301, Section 3.1
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionALPN)
		} else {
			exts.AddUint16(ExtensionALPN)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, proto := range m.alpnProtocols {
						exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
							exts.AddBytes([]byte(proto))
						})
					}
				})
			})
		}
	}
	if len(m.supportedVersions) > 0 {
		// RFC 8446, Section 4.2.1
		if echInner && outerExts == nil { // uTLS
			echOuterExts = append(echOuterExts, ExtensionSupportedVersions)
		} else {
			exts.AddUint16(ExtensionSupportedVersions)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, vers := range m.supportedVersions {
						exts.AddUint16(vers)
					}
				})
			})
		}
	}
	if len(m.cookie) > 0 {
		// RFC 8446, Section 4.2.2
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionCookie)
		} else {
			exts.AddUint16(ExtensionCookie)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes(m.cookie)
				})
			})
		}
	}
	if len(m.keyShares) > 0 {
		// RFC 8446, Section 4.2.8
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionKeyShare)
		} else {
			exts.AddUint16(ExtensionKeyShare)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
					for _, ks := range m.keyShares {
						exts.AddUint16(uint16(ks.group))
						exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
							exts.AddBytes(ks.data)
						})
					}
				})
			})
		}
	}
	if len(m.pskModes) > 0 {
		// RFC 8446, Section 4.2.9
		if echInner {
			echOuterExts = append(echOuterExts, ExtensionPSKModes)
		} else {
			exts.AddUint16(ExtensionPSKModes)
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes(m.pskModes)
				})
			})
		}
	}
	// [uTLS SECTION BEGIN]
	// reorder OuterExtensions according to their order in the spec
	if echInner && outerExts != nil {
		echOuterExtsReordered := slices.Collect(func(yield func(uint16) bool) {
			for _, ext := range outerExts {
				if slices.Contains(echOuterExts, ext) {
					if !yield(ext) {
						return
					}
				}
			}
		})
		echOuterExts = echOuterExtsReordered
	}
	// [uTLS SECTION END]
	if len(echOuterExts) > 0 && echInner {
		exts.AddUint16(extensionECHOuterExtensions)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, e := range echOuterExts {
					exts.AddUint16(e)
				}
			})
		})
	}
	if len(m.pskIdentities) > 0 { // pre_shared_key must be the last extension
		// RFC 8446, Section 4.2.11
		exts.AddUint16(ExtensionPreSharedKey)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, psk := range m.pskIdentities {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(psk.label)
					})
					exts.AddUint32(psk.obfuscatedTicketAge)
				}
			})
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, binder := range m.pskBinders {
					exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(binder)
					})
				}
			})
		})
	}
	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.vers)
		addBytesWithLength(b, m.random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			if !echInner {
				b.AddBytes(m.sessionId)
			}
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, suite := range m.cipherSuites {
				b.AddUint16(suite)
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.compressionMethods)
		})

		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extBytes)
			})
		}
	})

	return b.Bytes()
}

func (m *clientHelloMsg) marshal() ([]byte, error) {
	// [uTLS SECTION START]
	if m.original != nil {
		return m.original, nil
	}
	// [uTLS SECTION END]

	return m.marshalMsg(false)
}

// marshalWithoutBinders returns the ClientHello through the
// PreSharedKeyExtension.identities field, according to RFC 8446, Section
// 4.2.11.2. Note that m.pskBinders must be set to slices of the correct length.
func (m *clientHelloMsg) marshalWithoutBinders() ([]byte, error) {
	bindersLen := 2 // uint16 length prefix
	for _, binder := range m.pskBinders {
		bindersLen += 1 // uint8 length prefix
		bindersLen += len(binder)
	}

	var fullMessage []byte
	if m.original != nil {
		fullMessage = m.original
	} else {
		var err error
		fullMessage, err = m.marshal()
		if err != nil {
			return nil, err
		}
	}
	return fullMessage[:len(fullMessage)-bindersLen], nil
}

// updateBinders updates the m.pskBinders field. The supplied binders must have
// the same length as the current m.pskBinders.
func (m *clientHelloMsg) updateBinders(pskBinders [][]byte) error {
	if len(pskBinders) != len(m.pskBinders) {
		return errors.New("tls: internal error: pskBinders length mismatch")
	}
	for i := range m.pskBinders {
		if len(pskBinders[i]) != len(m.pskBinders[i]) {
			return errors.New("tls: internal error: pskBinders length mismatch")
		}
	}
	m.pskBinders = pskBinders

	return nil
}

func (m *clientHelloMsg) unmarshal(data []byte) bool {
	*m = clientHelloMsg{original: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) {
		return false
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return false
	}
	m.cipherSuites = []uint16{}
	m.secureRenegotiationSupported = false
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return false
		}
		if suite == scsvRenegotiation {
			m.secureRenegotiationSupported = true
		}
		m.cipherSuites = append(m.cipherSuites, suite)
	}

	if !readUint8LengthPrefixed(&s, &m.compressionMethods) {
		return false
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		if seenExts[extension] {
			return false
		}
		seenExts[extension] = true
		m.extensions = append(m.extensions, extension)

		switch extension {
		case ExtensionServerName:
			// RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return false
			}
			for !nameList.Empty() {
				var nameType uint8
				var serverName cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&serverName) ||
					serverName.Empty() {
					return false
				}
				if nameType != 0 {
					continue
				}
				if len(m.serverName) != 0 {
					// Multiple names of the same name_type are prohibited.
					return false
				}
				m.serverName = string(serverName)
				// An SNI value may not include a trailing dot.
				if strings.HasSuffix(m.serverName, ".") {
					return false
				}
			}
		case ExtensionNextProtoNeg:
			// draft-agl-tls-nextprotoneg-04
			m.nextProtoNeg = true
		case ExtensionStatusRequest:
			// RFC 4366, Section 3.6
			var statusType uint8
			var ignored cryptobyte.String
			if !extData.ReadUint8(&statusType) ||
				!extData.ReadUint16LengthPrefixed(&ignored) ||
				!extData.ReadUint16LengthPrefixed(&ignored) {
				return false
			}
			m.ocspStapling = statusType == statusTypeOCSP
		case ExtensionSupportedCurves:
			// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
			var curves cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&curves) || curves.Empty() {
				return false
			}
			for !curves.Empty() {
				var curve uint16
				if !curves.ReadUint16(&curve) {
					return false
				}
				m.supportedCurves = append(m.supportedCurves, CurveID(curve))
			}
		case ExtensionSupportedPoints:
			// RFC 4492, Section 5.1.2
			if !readUint8LengthPrefixed(&extData, &m.supportedPoints) ||
				len(m.supportedPoints) == 0 {
				return false
			}
		case ExtensionSessionTicket:
			// RFC 5077, Section 3.2
			m.ticketSupported = true
			extData.ReadBytes(&m.sessionTicket, len(extData))
		case ExtensionSignatureAlgorithms:
			// RFC 5246, Section 7.4.1.4.1
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithms = append(
					m.supportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
			}
		case ExtensionSignatureAlgorithmsCert:
			// RFC 8446, Section 4.2.3
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithmsCert = append(
					m.supportedSignatureAlgorithmsCert, SignatureScheme(sigAndAlg))
			}
		case ExtensionRenegotiationInfo:
			// RFC 5746, Section 3.2
			if !readUint8LengthPrefixed(&extData, &m.secureRenegotiation) {
				return false
			}
			m.secureRenegotiationSupported = true
		case ExtensionExtendedMasterSecret:
			// RFC 7627
			m.extendedMasterSecret = true
		case ExtensionALPN:
			// RFC 7301, Section 3.1
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			for !protoList.Empty() {
				var proto cryptobyte.String
				if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
					return false
				}
				m.alpnProtocols = append(m.alpnProtocols, string(proto))
			}
		case ExtensionSCT:
			// RFC 6962, Section 3.3.1
			m.scts = true
		case ExtensionSupportedVersions:
			// RFC 8446, Section 4.2.1
			var versList cryptobyte.String
			if !extData.ReadUint8LengthPrefixed(&versList) || versList.Empty() {
				return false
			}
			for !versList.Empty() {
				var vers uint16
				if !versList.ReadUint16(&vers) {
					return false
				}
				m.supportedVersions = append(m.supportedVersions, vers)
			}
		case ExtensionCookie:
			// RFC 8446, Section 4.2.2
			if !readUint16LengthPrefixed(&extData, &m.cookie) ||
				len(m.cookie) == 0 {
				return false
			}
		case ExtensionKeyShare:
			// RFC 8446, Section 4.2.8
			var clientShares cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&clientShares) {
				return false
			}
			for !clientShares.Empty() {
				var ks keyShare
				if !clientShares.ReadUint16((*uint16)(&ks.group)) ||
					!readUint16LengthPrefixed(&clientShares, &ks.data) ||
					len(ks.data) == 0 {
					return false
				}
				m.keyShares = append(m.keyShares, ks)
			}
		case ExtensionEarlyData:
			// RFC 8446, Section 4.2.10
			m.earlyData = true
		case ExtensionPSKModes:
			// RFC 8446, Section 4.2.9
			if !readUint8LengthPrefixed(&extData, &m.pskModes) {
				return false
			}
		case ExtensionQUICTransportParameters:
			m.quicTransportParameters = make([]byte, len(extData))
			if !extData.CopyBytes(m.quicTransportParameters) {
				return false
			}
		case ExtensionPreSharedKey:
			// RFC 8446, Section 4.2.11
			if !extensions.Empty() {
				return false // pre_shared_key must be the last extension
			}
			var identities cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&identities) || identities.Empty() {
				return false
			}
			for !identities.Empty() {
				var psk pskIdentity
				if !readUint16LengthPrefixed(&identities, &psk.label) ||
					!identities.ReadUint32(&psk.obfuscatedTicketAge) ||
					len(psk.label) == 0 {
					return false
				}
				m.pskIdentities = append(m.pskIdentities, psk)
			}
			var binders cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&binders) || binders.Empty() {
				return false
			}
			for !binders.Empty() {
				var binder []byte
				if !readUint8LengthPrefixed(&binders, &binder) ||
					len(binder) == 0 {
					return false
				}
				m.pskBinders = append(m.pskBinders, binder)
			}
		case extensionEncryptedClientHello:
			if !extData.ReadBytes(&m.encryptedClientHello, len(extData)) {
				return false
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

func (m *clientHelloMsg) originalBytes() []byte {
	return m.original
}

func (m *clientHelloMsg) clone() *clientHelloMsg {
	return &clientHelloMsg{
		original:                         slices.Clone(m.original),
		vers:                             m.vers,
		random:                           slices.Clone(m.random),
		sessionId:                        slices.Clone(m.sessionId),
		cipherSuites:                     slices.Clone(m.cipherSuites),
		compressionMethods:               slices.Clone(m.compressionMethods),
		serverName:                       m.serverName,
		ocspStapling:                     m.ocspStapling,
		supportedCurves:                  slices.Clone(m.supportedCurves),
		supportedPoints:                  slices.Clone(m.supportedPoints),
		ticketSupported:                  m.ticketSupported,
		sessionTicket:                    slices.Clone(m.sessionTicket),
		supportedSignatureAlgorithms:     slices.Clone(m.supportedSignatureAlgorithms),
		supportedSignatureAlgorithmsCert: slices.Clone(m.supportedSignatureAlgorithmsCert),
		secureRenegotiationSupported:     m.secureRenegotiationSupported,
		secureRenegotiation:              slices.Clone(m.secureRenegotiation),
		extendedMasterSecret:             m.extendedMasterSecret,
		alpnProtocols:                    slices.Clone(m.alpnProtocols),
		scts:                             m.scts,
		supportedVersions:                slices.Clone(m.supportedVersions),
		cookie:                           slices.Clone(m.cookie),
		keyShares:                        slices.Clone(m.keyShares),
		earlyData:                        m.earlyData,
		pskModes:                         slices.Clone(m.pskModes),
		pskIdentities:                    slices.Clone(m.pskIdentities),
		pskBinders:                       slices.Clone(m.pskBinders),
		quicTransportParameters:          slices.Clone(m.quicTransportParameters),
		encryptedClientHello:             slices.Clone(m.encryptedClientHello),
	}
}

type serverHelloMsg struct {
	original                     []byte
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cipherSuite                  uint16
	compressionMethod            uint8
	ocspStapling                 bool
	ticketSupported              bool
	secureRenegotiationSupported bool
	secureRenegotiation          []byte
	extendedMasterSecret         bool
	alpnProtocol                 string
	scts                         [][]byte
	supportedVersion             uint16
	serverShare                  keyShare
	selectedIdentityPresent      bool
	selectedIdentity             uint16
	supportedPoints              []uint8
	encryptedClientHello         []byte
	serverNameAck                bool

	// HelloRetryRequest extensions
	cookie        []byte
	selectedGroup CurveID

	// [uTLS]
	nextProtoNeg bool
	nextProtos   []string
}

func (m *serverHelloMsg) marshal() ([]byte, error) {
	var exts cryptobyte.Builder
	if m.nextProtoNeg {
		exts.AddUint16(ExtensionNextProtoNeg)
		exts.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, proto := range m.nextProtos {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(proto))
				})
			}
		})
	}
	if m.ocspStapling {
		exts.AddUint16(ExtensionStatusRequest)
		exts.AddUint16(0) // empty extension_data
	}
	if m.ticketSupported {
		exts.AddUint16(ExtensionSessionTicket)
		exts.AddUint16(0) // empty extension_data
	}
	if m.secureRenegotiationSupported {
		exts.AddUint16(ExtensionRenegotiationInfo)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.secureRenegotiation)
			})
		})
	}
	if m.extendedMasterSecret {
		exts.AddUint16(ExtensionExtendedMasterSecret)
		exts.AddUint16(0) // empty extension_data
	}
	if len(m.alpnProtocol) > 0 {
		exts.AddUint16(ExtensionALPN)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
					exts.AddBytes([]byte(m.alpnProtocol))
				})
			})
		})
	}
	if len(m.scts) > 0 {
		exts.AddUint16(ExtensionSCT)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				for _, sct := range m.scts {
					exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
						exts.AddBytes(sct)
					})
				}
			})
		})
	}
	if m.supportedVersion != 0 {
		exts.AddUint16(ExtensionSupportedVersions)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16(m.supportedVersion)
		})
	}
	if m.serverShare.group != 0 {
		exts.AddUint16(ExtensionKeyShare)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16(uint16(m.serverShare.group))
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.serverShare.data)
			})
		})
	}
	if m.selectedIdentityPresent {
		exts.AddUint16(ExtensionPreSharedKey)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16(m.selectedIdentity)
		})
	}

	if len(m.cookie) > 0 {
		exts.AddUint16(ExtensionCookie)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.cookie)
			})
		})
	}
	if m.selectedGroup != 0 {
		exts.AddUint16(ExtensionKeyShare)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint16(uint16(m.selectedGroup))
		})
	}
	if len(m.supportedPoints) > 0 {
		exts.AddUint16(ExtensionSupportedPoints)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddUint8LengthPrefixed(func(exts *cryptobyte.Builder) {
				exts.AddBytes(m.supportedPoints)
			})
		})
	}
	if len(m.encryptedClientHello) > 0 {
		exts.AddUint16(extensionEncryptedClientHello)
		exts.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			exts.AddBytes(m.encryptedClientHello)
		})
	}
	if m.serverNameAck {
		exts.AddUint16(ExtensionServerName)
		exts.AddUint16(0)
	}

	extBytes, err := exts.Bytes()
	if err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint8(typeServerHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.vers)
		addBytesWithLength(b, m.random, 32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.sessionId)
		})
		b.AddUint16(m.cipherSuite)
		b.AddUint8(m.compressionMethod)

		if len(extBytes) > 0 {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extBytes)
			})
		}
	})

	return b.Bytes()
}

func (m *serverHelloMsg) unmarshal(data []byte) bool {
	*m = serverHelloMsg{original: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.vers) || !s.ReadBytes(&m.random, 32) ||
		!readUint8LengthPrefixed(&s, &m.sessionId) ||
		!s.ReadUint16(&m.cipherSuite) ||
		!s.ReadUint8(&m.compressionMethod) {
		return false
	}

	if s.Empty() {
		// ServerHello is optionally followed by extension data
		return true
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	seenExts := make(map[uint16]bool)
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		if seenExts[extension] {
			return false
		}
		seenExts[extension] = true

		switch extension {
		case ExtensionNextProtoNeg:
			m.nextProtoNeg = true
			for !extData.Empty() {
				var proto cryptobyte.String
				if !extData.ReadUint8LengthPrefixed(&proto) ||
					proto.Empty() {
					return false
				}
				m.nextProtos = append(m.nextProtos, string(proto))
			}
		case ExtensionStatusRequest:
			m.ocspStapling = true
		case ExtensionSessionTicket:
			m.ticketSupported = true
		// [UTLS] crypto/tls finally supports EMS! Now we don't do anything special here.
		// case ExtensionExtendedMasterSecret:
		// 	// No sanity check for this extension: pretending not to know it.
		// 	// if length > 0 {
		// 	// 	return false
		// 	// }
		// 	m.ems = true
		case ExtensionRenegotiationInfo:
			if !readUint8LengthPrefixed(&extData, &m.secureRenegotiation) {
				return false
			}
			m.secureRenegotiationSupported = true
		case ExtensionExtendedMasterSecret:
			m.extendedMasterSecret = true
		case ExtensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return false
			}
			m.alpnProtocol = string(proto)
		case ExtensionSCT:
			var sctList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
				return false
			}
			for !sctList.Empty() {
				var sct []byte
				if !readUint16LengthPrefixed(&sctList, &sct) ||
					len(sct) == 0 {
					return false
				}
				m.scts = append(m.scts, sct)
			}
		case ExtensionSupportedVersions:
			if !extData.ReadUint16(&m.supportedVersion) {
				return false
			}
		case ExtensionCookie:
			if !readUint16LengthPrefixed(&extData, &m.cookie) ||
				len(m.cookie) == 0 {
				return false
			}
		case ExtensionKeyShare:
			// This extension has different formats in SH and HRR, accept either
			// and let the handshake logic decide. See RFC 8446, Section 4.2.8.
			if len(extData) == 2 {
				if !extData.ReadUint16((*uint16)(&m.selectedGroup)) {
					return false
				}
			} else {
				if !extData.ReadUint16((*uint16)(&m.serverShare.group)) ||
					!readUint16LengthPrefixed(&extData, &m.serverShare.data) {
					return false
				}
			}
		case ExtensionPreSharedKey:
			m.selectedIdentityPresent = true
			if !extData.ReadUint16(&m.selectedIdentity) {
				return false
			}
		case ExtensionSupportedPoints:
			// RFC 4492, Section 5.1.2
			if !readUint8LengthPrefixed(&extData, &m.supportedPoints) ||
				len(m.supportedPoints) == 0 {
				return false
			}
		case extensionEncryptedClientHello: // encrypted_client_hello
			m.encryptedClientHello = make([]byte, len(extData))
			if !extData.CopyBytes(m.encryptedClientHello) {
				return false
			}
		case ExtensionServerName:
			if len(extData) != 0 {
				return false
			}
			m.serverNameAck = true
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

func (m *serverHelloMsg) originalBytes() []byte {
	return m.original
}

type encryptedExtensionsMsg struct {
	alpnProtocol            string
	quicTransportParameters []byte
	earlyData               bool
	echRetryConfigs         []byte

	utls utlsEncryptedExtensionsMsgExtraFields // [uTLS]
}

func (m *encryptedExtensionsMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeEncryptedExtensions)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if len(m.alpnProtocol) > 0 {
				b.AddUint16(ExtensionALPN)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(m.alpnProtocol))
						})
					})
				})
			}
			if m.quicTransportParameters != nil { // marshal zero-length parameters when present
				// draft-ietf-quic-tls-32, Section 8.2
				b.AddUint16(ExtensionQUICTransportParameters)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(m.quicTransportParameters)
				})
			}
			if m.earlyData {
				// RFC 8446, Section 4.2.10
				b.AddUint16(ExtensionEarlyData)
				b.AddUint16(0) // empty extension_data
			}
			if len(m.echRetryConfigs) > 0 {
				b.AddUint16(extensionEncryptedClientHello)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(m.echRetryConfigs)
				})
			}
		})
	})

	return b.Bytes()
}

func (m *encryptedExtensionsMsg) unmarshal(data []byte) bool {
	*m = encryptedExtensionsMsg{}
	s := cryptobyte.String(data)

	var extensions cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case ExtensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return false
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return false
			}
			m.alpnProtocol = string(proto)
		case ExtensionQUICTransportParameters:
			m.quicTransportParameters = make([]byte, len(extData))
			if !extData.CopyBytes(m.quicTransportParameters) {
				return false
			}
		case ExtensionEarlyData:
			// RFC 8446, Section 4.2.10
			m.earlyData = true
		case extensionEncryptedClientHello:
			m.echRetryConfigs = make([]byte, len(extData))
			if !extData.CopyBytes(m.echRetryConfigs) {
				return false
			}
		default:
			// [UTLS SECTION START]
			if !m.utlsUnmarshal(extension, extData) {
				return false // return false when ERROR
			}
			// [UTLS SECTION END]
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

type endOfEarlyDataMsg struct{}

func (m *endOfEarlyDataMsg) marshal() ([]byte, error) {
	x := make([]byte, 4)
	x[0] = typeEndOfEarlyData
	return x, nil
}

func (m *endOfEarlyDataMsg) unmarshal(data []byte) bool {
	return len(data) == 4
}

type keyUpdateMsg struct {
	updateRequested bool
}

func (m *keyUpdateMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeKeyUpdate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		if m.updateRequested {
			b.AddUint8(1)
		} else {
			b.AddUint8(0)
		}
	})

	return b.Bytes()
}

func (m *keyUpdateMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var updateRequested uint8
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint8(&updateRequested) || !s.Empty() {
		return false
	}
	switch updateRequested {
	case 0:
		m.updateRequested = false
	case 1:
		m.updateRequested = true
	default:
		return false
	}
	return true
}

type newSessionTicketMsgTLS13 struct {
	lifetime     uint32
	ageAdd       uint32
	nonce        []byte
	label        []byte
	maxEarlyData uint32
}

func (m *newSessionTicketMsgTLS13) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeNewSessionTicket)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint32(m.lifetime)
		b.AddUint32(m.ageAdd)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.nonce)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.label)
		})

		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if m.maxEarlyData > 0 {
				b.AddUint16(ExtensionEarlyData)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint32(m.maxEarlyData)
				})
			}
		})
	})

	return b.Bytes()
}

func (m *newSessionTicketMsgTLS13) unmarshal(data []byte) bool {
	*m = newSessionTicketMsgTLS13{}
	s := cryptobyte.String(data)

	var extensions cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint32(&m.lifetime) ||
		!s.ReadUint32(&m.ageAdd) ||
		!readUint8LengthPrefixed(&s, &m.nonce) ||
		!readUint16LengthPrefixed(&s, &m.label) ||
		!s.ReadUint16LengthPrefixed(&extensions) ||
		!s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case ExtensionEarlyData:
			if !extData.ReadUint32(&m.maxEarlyData) {
				return false
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

type certificateRequestMsgTLS13 struct {
	ocspStapling                     bool
	scts                             bool
	supportedSignatureAlgorithms     []SignatureScheme
	supportedSignatureAlgorithmsCert []SignatureScheme
	certificateAuthorities           [][]byte
}

func (m *certificateRequestMsgTLS13) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificateRequest)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		// certificate_request_context (SHALL be zero length unless used for
		// post-handshake authentication)
		b.AddUint8(0)

		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			if m.ocspStapling {
				b.AddUint16(ExtensionStatusRequest)
				b.AddUint16(0) // empty extension_data
			}
			if m.scts {
				// RFC 8446, Section 4.4.2.1 makes no mention of
				// signed_certificate_timestamp in CertificateRequest, but
				// "Extensions in the Certificate message from the client MUST
				// correspond to extensions in the CertificateRequest message
				// from the server." and it appears in the table in Section 4.2.
				b.AddUint16(ExtensionSCT)
				b.AddUint16(0) // empty extension_data
			}
			if len(m.supportedSignatureAlgorithms) > 0 {
				b.AddUint16(ExtensionSignatureAlgorithms)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, sigAlgo := range m.supportedSignatureAlgorithms {
							b.AddUint16(uint16(sigAlgo))
						}
					})
				})
			}
			if len(m.supportedSignatureAlgorithmsCert) > 0 {
				b.AddUint16(ExtensionSignatureAlgorithmsCert)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, sigAlgo := range m.supportedSignatureAlgorithmsCert {
							b.AddUint16(uint16(sigAlgo))
						}
					})
				})
			}
			if len(m.certificateAuthorities) > 0 {
				b.AddUint16(ExtensionCertificateAuthorities)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, ca := range m.certificateAuthorities {
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
								b.AddBytes(ca)
							})
						}
					})
				})
			}
		})
	})

	return b.Bytes()
}

func (m *certificateRequestMsgTLS13) unmarshal(data []byte) bool {
	*m = certificateRequestMsgTLS13{}
	s := cryptobyte.String(data)

	var context, extensions cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint8LengthPrefixed(&context) || !context.Empty() ||
		!s.ReadUint16LengthPrefixed(&extensions) ||
		!s.Empty() {
		return false
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return false
		}

		switch extension {
		case ExtensionStatusRequest:
			m.ocspStapling = true
		case ExtensionSCT:
			m.scts = true
		case ExtensionSignatureAlgorithms:
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithms = append(
					m.supportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
			}
		case ExtensionSignatureAlgorithmsCert:
			var sigAndAlgs cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
				return false
			}
			for !sigAndAlgs.Empty() {
				var sigAndAlg uint16
				if !sigAndAlgs.ReadUint16(&sigAndAlg) {
					return false
				}
				m.supportedSignatureAlgorithmsCert = append(
					m.supportedSignatureAlgorithmsCert, SignatureScheme(sigAndAlg))
			}
		case ExtensionCertificateAuthorities:
			var auths cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&auths) || auths.Empty() {
				return false
			}
			for !auths.Empty() {
				var ca []byte
				if !readUint16LengthPrefixed(&auths, &ca) || len(ca) == 0 {
					return false
				}
				m.certificateAuthorities = append(m.certificateAuthorities, ca)
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return false
		}
	}

	return true
}

type certificateMsg struct {
	certificates [][]byte
}

func (m *certificateMsg) marshal() ([]byte, error) {
	var i int
	for _, slice := range m.certificates {
		i += len(slice)
	}

	length := 3 + 3*len(m.certificates) + i
	x := make([]byte, 4+length)
	x[0] = typeCertificate
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	certificateOctets := length - 3
	x[4] = uint8(certificateOctets >> 16)
	x[5] = uint8(certificateOctets >> 8)
	x[6] = uint8(certificateOctets)

	y := x[7:]
	for _, slice := range m.certificates {
		y[0] = uint8(len(slice) >> 16)
		y[1] = uint8(len(slice) >> 8)
		y[2] = uint8(len(slice))
		copy(y[3:], slice)
		y = y[3+len(slice):]
	}

	return x, nil
}

func (m *certificateMsg) unmarshal(data []byte) bool {
	if len(data) < 7 {
		return false
	}

	certsLen := uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])
	if uint32(len(data)) != certsLen+7 {
		return false
	}

	numCerts := 0
	d := data[7:]
	for certsLen > 0 {
		if len(d) < 4 {
			return false
		}
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		if uint32(len(d)) < 3+certLen {
			return false
		}
		d = d[3+certLen:]
		certsLen -= 3 + certLen
		numCerts++
	}

	m.certificates = make([][]byte, numCerts)
	d = data[7:]
	for i := 0; i < numCerts; i++ {
		certLen := uint32(d[0])<<16 | uint32(d[1])<<8 | uint32(d[2])
		m.certificates[i] = d[3 : 3+certLen]
		d = d[3+certLen:]
	}

	return true
}

type certificateMsgTLS13 struct {
	certificate  Certificate
	ocspStapling bool
	scts         bool
}

func (m *certificateMsgTLS13) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // certificate_request_context

		certificate := m.certificate
		if !m.ocspStapling {
			certificate.OCSPStaple = nil
		}
		if !m.scts {
			certificate.SignedCertificateTimestamps = nil
		}
		marshalCertificate(b, certificate)
	})

	return b.Bytes()
}

func marshalCertificate(b *cryptobyte.Builder, certificate Certificate) {
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for i, cert := range certificate.Certificate {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(cert)
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				if i > 0 {
					// This library only supports OCSP and SCT for leaf certificates.
					return
				}
				if certificate.OCSPStaple != nil {
					b.AddUint16(ExtensionStatusRequest)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8(statusTypeOCSP)
						b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes(certificate.OCSPStaple)
						})
					})
				}
				if certificate.SignedCertificateTimestamps != nil {
					b.AddUint16(ExtensionSCT)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							for _, sct := range certificate.SignedCertificateTimestamps {
								b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
									b.AddBytes(sct)
								})
							}
						})
					})
				}
			})
		}
	})
}

func (m *certificateMsgTLS13) unmarshal(data []byte) bool {
	*m = certificateMsgTLS13{}
	s := cryptobyte.String(data)

	var context cryptobyte.String
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint8LengthPrefixed(&context) || !context.Empty() ||
		!unmarshalCertificate(&s, &m.certificate) ||
		!s.Empty() {
		return false
	}

	m.scts = m.certificate.SignedCertificateTimestamps != nil
	m.ocspStapling = m.certificate.OCSPStaple != nil

	return true
}

func unmarshalCertificate(s *cryptobyte.String, certificate *Certificate) bool {
	var certList cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&certList) {
		return false
	}
	for !certList.Empty() {
		var cert []byte
		var extensions cryptobyte.String
		if !readUint24LengthPrefixed(&certList, &cert) ||
			!certList.ReadUint16LengthPrefixed(&extensions) {
			return false
		}
		certificate.Certificate = append(certificate.Certificate, cert)
		for !extensions.Empty() {
			var extension uint16
			var extData cryptobyte.String
			if !extensions.ReadUint16(&extension) ||
				!extensions.ReadUint16LengthPrefixed(&extData) {
				return false
			}
			if len(certificate.Certificate) > 1 {
				// This library only supports OCSP and SCT for leaf certificates.
				continue
			}

			switch extension {
			case ExtensionStatusRequest:
				var statusType uint8
				if !extData.ReadUint8(&statusType) || statusType != statusTypeOCSP ||
					!readUint24LengthPrefixed(&extData, &certificate.OCSPStaple) ||
					len(certificate.OCSPStaple) == 0 {
					return false
				}
			case ExtensionSCT:
				var sctList cryptobyte.String
				if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
					return false
				}
				for !sctList.Empty() {
					var sct []byte
					if !readUint16LengthPrefixed(&sctList, &sct) ||
						len(sct) == 0 {
						return false
					}
					certificate.SignedCertificateTimestamps = append(
						certificate.SignedCertificateTimestamps, sct)
				}
			default:
				// Ignore unknown extensions.
				continue
			}

			if !extData.Empty() {
				return false
			}
		}
	}
	return true
}

type serverKeyExchangeMsg struct {
	key []byte
}

func (m *serverKeyExchangeMsg) marshal() ([]byte, error) {
	length := len(m.key)
	x := make([]byte, length+4)
	x[0] = typeServerKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.key)

	return x, nil
}

func (m *serverKeyExchangeMsg) unmarshal(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	m.key = data[4:]
	return true
}

type certificateStatusMsg struct {
	response []byte
}

func (m *certificateStatusMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificateStatus)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(statusTypeOCSP)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.response)
		})
	})

	return b.Bytes()
}

func (m *certificateStatusMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	var statusType uint8
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint8(&statusType) || statusType != statusTypeOCSP ||
		!readUint24LengthPrefixed(&s, &m.response) ||
		len(m.response) == 0 || !s.Empty() {
		return false
	}
	return true
}

type serverHelloDoneMsg struct{}

func (m *serverHelloDoneMsg) marshal() ([]byte, error) {
	x := make([]byte, 4)
	x[0] = typeServerHelloDone
	return x, nil
}

func (m *serverHelloDoneMsg) unmarshal(data []byte) bool {
	return len(data) == 4
}

type clientKeyExchangeMsg struct {
	ciphertext []byte
}

func (m *clientKeyExchangeMsg) marshal() ([]byte, error) {
	length := len(m.ciphertext)
	x := make([]byte, length+4)
	x[0] = typeClientKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.ciphertext)

	return x, nil
}

func (m *clientKeyExchangeMsg) unmarshal(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	l := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if l != len(data)-4 {
		return false
	}
	m.ciphertext = data[4:]
	return true
}

type finishedMsg struct {
	verifyData []byte
}

func (m *finishedMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeFinished)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(m.verifyData)
	})

	return b.Bytes()
}

func (m *finishedMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)
	return s.Skip(1) &&
		readUint24LengthPrefixed(&s, &m.verifyData) &&
		s.Empty()
}

type certificateRequestMsg struct {
	// hasSignatureAlgorithm indicates whether this message includes a list of
	// supported signature algorithms. This change was introduced with TLS 1.2.
	hasSignatureAlgorithm bool

	certificateTypes             []byte
	supportedSignatureAlgorithms []SignatureScheme
	certificateAuthorities       [][]byte
}

func (m *certificateRequestMsg) marshal() ([]byte, error) {
	// See RFC 4346, Section 7.4.4.
	length := 1 + len(m.certificateTypes) + 2
	casLength := 0
	for _, ca := range m.certificateAuthorities {
		casLength += 2 + len(ca)
	}
	length += casLength

	if m.hasSignatureAlgorithm {
		length += 2 + 2*len(m.supportedSignatureAlgorithms)
	}

	x := make([]byte, 4+length)
	x[0] = typeCertificateRequest
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)

	x[4] = uint8(len(m.certificateTypes))

	copy(x[5:], m.certificateTypes)
	y := x[5+len(m.certificateTypes):]

	if m.hasSignatureAlgorithm {
		n := len(m.supportedSignatureAlgorithms) * 2
		y[0] = uint8(n >> 8)
		y[1] = uint8(n)
		y = y[2:]
		for _, sigAlgo := range m.supportedSignatureAlgorithms {
			y[0] = uint8(sigAlgo >> 8)
			y[1] = uint8(sigAlgo)
			y = y[2:]
		}
	}

	y[0] = uint8(casLength >> 8)
	y[1] = uint8(casLength)
	y = y[2:]
	for _, ca := range m.certificateAuthorities {
		y[0] = uint8(len(ca) >> 8)
		y[1] = uint8(len(ca))
		y = y[2:]
		copy(y, ca)
		y = y[len(ca):]
	}

	return x, nil
}

func (m *certificateRequestMsg) unmarshal(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return false
	}

	numCertTypes := int(data[4])
	data = data[5:]
	if numCertTypes == 0 || len(data) <= numCertTypes {
		return false
	}

	m.certificateTypes = make([]byte, numCertTypes)
	if copy(m.certificateTypes, data) != numCertTypes {
		return false
	}

	data = data[numCertTypes:]

	if m.hasSignatureAlgorithm {
		if len(data) < 2 {
			return false
		}
		sigAndHashLen := uint16(data[0])<<8 | uint16(data[1])
		data = data[2:]
		if sigAndHashLen&1 != 0 {
			return false
		}
		if len(data) < int(sigAndHashLen) {
			return false
		}
		numSigAlgos := sigAndHashLen / 2
		m.supportedSignatureAlgorithms = make([]SignatureScheme, numSigAlgos)
		for i := range m.supportedSignatureAlgorithms {
			m.supportedSignatureAlgorithms[i] = SignatureScheme(data[0])<<8 | SignatureScheme(data[1])
			data = data[2:]
		}
	}

	if len(data) < 2 {
		return false
	}
	casLength := uint16(data[0])<<8 | uint16(data[1])
	data = data[2:]
	if len(data) < int(casLength) {
		return false
	}
	cas := make([]byte, casLength)
	copy(cas, data)
	data = data[casLength:]

	m.certificateAuthorities = nil
	for len(cas) > 0 {
		if len(cas) < 2 {
			return false
		}
		caLen := uint16(cas[0])<<8 | uint16(cas[1])
		cas = cas[2:]

		if len(cas) < int(caLen) {
			return false
		}

		m.certificateAuthorities = append(m.certificateAuthorities, cas[:caLen])
		cas = cas[caLen:]
	}

	return len(data) == 0
}

type certificateVerifyMsg struct {
	hasSignatureAlgorithm bool // format change introduced in TLS 1.2
	signatureAlgorithm    SignatureScheme
	signature             []byte
}

func (m *certificateVerifyMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificateVerify)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		if m.hasSignatureAlgorithm {
			b.AddUint16(uint16(m.signatureAlgorithm))
		}
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.signature)
		})
	})

	return b.Bytes()
}

func (m *certificateVerifyMsg) unmarshal(data []byte) bool {
	s := cryptobyte.String(data)

	if !s.Skip(4) { // message type and uint24 length field
		return false
	}
	if m.hasSignatureAlgorithm {
		if !s.ReadUint16((*uint16)(&m.signatureAlgorithm)) {
			return false
		}
	}
	return readUint16LengthPrefixed(&s, &m.signature) && s.Empty()
}

type newSessionTicketMsg struct {
	ticket []byte
}

func (m *newSessionTicketMsg) marshal() ([]byte, error) {
	// See RFC 5077, Section 3.3.
	ticketLen := len(m.ticket)
	length := 2 + 4 + ticketLen
	x := make([]byte, 4+length)
	x[0] = typeNewSessionTicket
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[8] = uint8(ticketLen >> 8)
	x[9] = uint8(ticketLen)
	copy(x[10:], m.ticket)

	return x, nil
}

func (m *newSessionTicketMsg) unmarshal(data []byte) bool {
	if len(data) < 10 {
		return false
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return false
	}

	ticketLen := int(data[8])<<8 + int(data[9])
	if len(data)-10 != ticketLen {
		return false
	}

	m.ticket = data[10:]

	return true
}

type helloRequestMsg struct {
}

func (*helloRequestMsg) marshal() ([]byte, error) {
	return []byte{typeHelloRequest, 0, 0, 0}, nil
}

func (*helloRequestMsg) unmarshal(data []byte) bool {
	return len(data) == 4
}

type transcriptHash interface {
	Write([]byte) (int, error)
}

// transcriptMsg is a helper used to hash messages which are not hashed when
// they are read from, or written to, the wire. This is typically the case for
// messages which are either not sent, or need to be hashed out of order from
// when they are read/written.
//
// For most messages, the message is marshalled using their marshal method,
// since their wire representation is idempotent. For clientHelloMsg and
// serverHelloMsg, we store the original wire representation of the message and
// use that for hashing, since unmarshal/marshal are not idempotent due to
// extension ordering and other malleable fields, which may cause differences
// between what was received and what we marshal.
func transcriptMsg(msg handshakeMessage, h transcriptHash) error {
	if msgWithOrig, ok := msg.(handshakeMessageWithOriginalBytes); ok {
		if orig := msgWithOrig.originalBytes(); orig != nil {
			h.Write(msgWithOrig.originalBytes())
			return nil
		}
	}

	data, err := msg.marshal()
	if err != nil {
		return err
	}
	h.Write(data)
	return nil
}
