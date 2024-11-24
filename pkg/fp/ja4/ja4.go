package ja4

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/qencept/gofp/pkg/tls/clienthello"
	"github.com/qencept/gofp/pkg/tls/record"
)

type JA4 struct {
	fp string
}

func New(hello *clienthello.ClientHello) *JA4 {
	fp := fmt.Sprintf("%v_%x_%x", partA(hello), partB(hello)[:6], partC(hello)[:6])
	return &JA4{fp: fp}
}

func (ja4 *JA4) String() string {
	return ja4.fp
}

func partA(hello *clienthello.ClientHello) string {
	str := "t"
	str += map[uint16]string{
		record.VersionTLS13: "13",
		record.VersionTLS12: "12",
		record.VersionTLS11: "11",
		record.VersionTLS10: "10",
	}[slices.Max(hello.ExtensionSupportedVersions)]
	if len(hello.ExtensionSNI) > 0 {
		str += "d"
	} else {
		str += "i"
	}
	str += fmt.Sprintf("%02d", len(hello.CipherSuites))
	str += fmt.Sprintf("%02d", len(hello.ExtensionTypes))
	if len(hello.ExtensionALPN) > 0 && len(hello.ExtensionALPN[0]) > 0 {
		str += string(hello.ExtensionALPN[0][0]) + string(hello.ExtensionALPN[0][len(hello.ExtensionALPN[0])-1])
	} else {
		str += "00"
	}
	return str
}

func partB(hello *clienthello.ClientHello) []byte {
	cipherSuites := append([]uint16(nil), hello.CipherSuites...)
	sort.Slice(cipherSuites, func(i, j int) bool {
		return cipherSuites[i] < cipherSuites[j]
	})
	str := stringList(cipherSuites...)
	h := sha256.New()
	h.Write([]byte(str))
	return h.Sum(nil)
}

func partC(hello *clienthello.ClientHello) []byte {
	extensionTypes := append([]uint16(nil), hello.ExtensionTypes...)
	sort.Slice(extensionTypes, func(i, j int) bool {
		return extensionTypes[i] < extensionTypes[j]
	})
	str1 := stringExcludeList(map[uint16]bool{clienthello.ExtensionSNI: true, clienthello.ExtensionALPN: true}, extensionTypes...)
	str2 := stringList(hello.ExtensionSignatures...)
	str := str1 + "_" + str2
	h := sha256.New()
	h.Write([]byte(str))
	return h.Sum(nil)
}

func stringList(slice ...uint16) string {
	return stringExcludeList(make(map[uint16]bool), slice...)
}

func stringExcludeList(excludes map[uint16]bool, slice ...uint16) string {
	b := strings.Builder{}
	for i, item := range slice {
		if excludes[item] {
			continue
		}
		b.WriteString(fmt.Sprintf("%04x", item))
		if i != len(slice)-1 {
			b.WriteString(",")
		}
	}

	return b.String()
}
