package ja4s

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/qencept/gofp/pkg/tls/clienthello"
	"github.com/qencept/gofp/pkg/tls/record"
	"github.com/qencept/gofp/pkg/tls/serverhello"
)

type JA4 struct {
	fp string
}

func New(hello *serverhello.ServerHello) *JA4 {
	fp := fmt.Sprintf("%v_%v_%x", partA(hello), partB(hello), partC(hello)[:6])
	return &JA4{fp: fp}
}

func (ja4 *JA4) String() string {
	return ja4.fp
}

func partA(hello *serverhello.ServerHello) string {
	str := "t"

	str += map[uint16]string{
		record.VersionTLS13: "13",
		record.VersionTLS12: "12",
		record.VersionTLS11: "11",
		record.VersionTLS10: "10",
	}[slices.Max([]uint16{hello.ExtensionSupportedVersion, hello.Version})]
	str += fmt.Sprintf("%02d", len(hello.ExtensionTypes))
	if len(hello.ExtensionALPN) > 0 {
		str += string(hello.ExtensionALPN[0]) + string(hello.ExtensionALPN[len(hello.ExtensionALPN)-1])
	} else {
		str += "00"
	}
	return str
}

func partB(hello *serverhello.ServerHello) string {
	return fmt.Sprintf("%04x", hello.CipherSuite)
}

func partC(hello *serverhello.ServerHello) []byte {
	extensionTypes := append([]uint16(nil), hello.ExtensionTypes...)
	sort.Slice(extensionTypes, func(i, j int) bool {
		return extensionTypes[i] < extensionTypes[j]
	})
	str := stringExcludeList(map[uint16]bool{clienthello.ExtensionSNI: true, clienthello.ExtensionALPN: true}, extensionTypes...)
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
