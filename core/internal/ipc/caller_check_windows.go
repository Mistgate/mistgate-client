//go:build windows

package ipc

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type signatureFacts struct {
	Signed     bool
	Valid      bool
	Thumbprint string
}

func executablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Abs(path)
}

func developmentClientPath() string {
	path := strings.TrimSpace(os.Getenv("MISTGATE_DEV_CLIENT"))
	if path == "" {
		return ""
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	return absolute
}

func processImagePath(process windows.Handle) (string, error) {
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(process, 0, &buffer[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buffer[:size]), nil
}

func inspectSignature(path string) signatureFacts {
	signed := hasEmbeddedSignature(path)
	if !signed {
		return signatureFacts{}
	}
	thumbprint, err := signerThumbprint(path)
	if err != nil {
		return signatureFacts{Signed: true}
	}
	valid := verifyAuthenticode(path) == nil
	return signatureFacts{Signed: true, Valid: valid, Thumbprint: thumbprint}
}

func inspectCallerSignature(path, servicePath string, serviceSigned bool) (signatureFacts, bool) {
	return inspectCallerSignatureWith(path, servicePath, serviceSigned, driveType, inspectSignature)
}

func inspectCallerSignatureWith(path, servicePath string, serviceSigned bool, drive func(string) uint32, inspect func(string) signatureFacts) (signatureFacts, bool) {
	if !callerPathMayBeInspected(path, servicePath, serviceSigned, drive) {
		return signatureFacts{}, false
	}
	return inspect(path), true
}

func callerPathMayBeInspected(path, servicePath string, serviceSigned bool, drive func(string) uint32) bool {
	path = strings.ReplaceAll(strings.TrimSpace(path), "/", `\`)
	lower := strings.ToLower(path)
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(lower, `\device\`) || strings.HasPrefix(lower, `\??\`) || strings.HasPrefix(lower, `\global??\`) {
		return false
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return false
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		return false
	}
	if !serviceSigned {
		servicePath = filepath.Clean(strings.ReplaceAll(strings.TrimSpace(servicePath), "/", `\`))
		if !filepath.IsAbs(servicePath) || !strings.EqualFold(filepath.VolumeName(servicePath), volume) {
			return false
		}
		dir := filepath.Dir(servicePath)
		caller := strings.ToLower(strings.TrimRight(path, `\`))
		directory := strings.ToLower(strings.TrimRight(dir, `\`))
		if caller != directory && !strings.HasPrefix(caller, directory+`\`) {
			return false
		}
	}
	root := volume + `\`
	return drive(root) == windows.DRIVE_FIXED
}

func driveType(root string) uint32 {
	root16, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return windows.DRIVE_UNKNOWN
	}
	return windows.GetDriveType(root16)
}

// ponytail: this slice recognizes embedded PE signatures; catalog-only signatures are not detected.
func hasEmbeddedSignature(path string) bool {
	// Keep signed-but-invalid files out of the unsigned development fallback.
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	dosHeader := make([]byte, 64)
	if _, err := file.ReadAt(dosHeader, 0); err != nil || string(dosHeader[:2]) != "MZ" {
		return false
	}
	peOffset := int64(binary.LittleEndian.Uint32(dosHeader[0x3c:0x40]))
	peHeader := make([]byte, 24)
	if _, err := file.ReadAt(peHeader, peOffset); err != nil || string(peHeader[:4]) != "PE\x00\x00" {
		return false
	}
	optionalSize := int(binary.LittleEndian.Uint16(peHeader[20:22]))
	if optionalSize < 2 {
		return false
	}
	optional := make([]byte, optionalSize)
	if _, err := file.ReadAt(optional, peOffset+24); err != nil {
		return false
	}
	var securityDirectoryOffset int
	switch binary.LittleEndian.Uint16(optional[:2]) {
	case 0x10b:
		securityDirectoryOffset = 96 + 4*8
	case 0x20b:
		securityDirectoryOffset = 112 + 4*8
	default:
		return false
	}
	if len(optional) < securityDirectoryOffset+8 {
		return false
	}
	return binary.LittleEndian.Uint32(optional[securityDirectoryOffset+4:securityDirectoryOffset+8]) != 0
}

func verifyAuthenticode(path string) error {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	data := &windows.WinTrustData{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice: windows.WTD_UI_NONE,
		// Caller validation must not fetch revocation data over the network.
		RevocationChecks: windows.WTD_REVOKE_NONE,
		UnionChoice:      windows.WTD_CHOICE_FILE,
		StateAction:      windows.WTD_STATEACTION_VERIFY,
		ProvFlags:        windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&windows.WinTrustFileInfo{
			Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
			FilePath: path16,
		}),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return verifyErr
}

func signerThumbprint(path string) (string, error) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var encoding, contentType, formatType uint32
	var store, message windows.Handle
	err = windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(path16),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&encoding,
		&contentType,
		&formatType,
		&store,
		&message,
		nil,
	)
	if err != nil {
		return "", err
	}
	defer windows.CertCloseStore(store, 0)
	defer closeCryptMessage(message)

	certificateInfo, err := signerCertificateInfo(message)
	if err != nil {
		return "", err
	}
	var previous *windows.CertContext
	for {
		certificate, enumErr := windows.CertEnumCertificatesInStore(store, previous)
		if certificate == nil {
			return "", enumErr
		}
		previous = certificate
		if certificate.CertInfo == nil || !sameCertificateID(certificate.CertInfo, certificateInfo) {
			continue
		}
		der := unsafe.Slice(certificate.EncodedCert, int(certificate.Length))
		thumbprint := sha1.Sum(der)
		_ = windows.CertFreeCertificateContext(certificate)
		return strings.ToUpper(hex.EncodeToString(thumbprint[:])), nil
	}
}

func signerCertificateInfo(message windows.Handle) (*windows.CertInfo, error) {
	getParam := windows.NewLazySystemDLL("crypt32.dll").NewProc("CryptMsgGetParam")
	if err := getParam.Find(); err != nil {
		return nil, err
	}
	const signerCertInfoParam = 7
	var size uint32
	_, _, _ = getParam.Call(uintptr(message), signerCertInfoParam, 0, 0, uintptr(unsafe.Pointer(&size)))
	if size < uint32(unsafe.Sizeof(windows.CertInfo{})) {
		return nil, errors.New("Authenticode signer information is missing")
	}
	buffer := make([]byte, size)
	result, _, callErr := getParam.Call(
		uintptr(message),
		signerCertInfoParam,
		0,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if result == 0 {
		return nil, callErr
	}
	return (*windows.CertInfo)(unsafe.Pointer(&buffer[0])), nil
}

func sameCertificateID(left, right *windows.CertInfo) bool {
	return sameBlob(left.Issuer.Data, left.Issuer.Size, right.Issuer.Data, right.Issuer.Size) &&
		sameBlob(left.SerialNumber.Data, left.SerialNumber.Size, right.SerialNumber.Data, right.SerialNumber.Size)
}

func sameBlob(left *byte, leftSize uint32, right *byte, rightSize uint32) bool {
	if leftSize != rightSize {
		return false
	}
	if leftSize == 0 {
		return true
	}
	return string(unsafe.Slice(left, int(leftSize))) == string(unsafe.Slice(right, int(rightSize)))
}

func closeCryptMessage(message windows.Handle) {
	closeMessage := windows.NewLazySystemDLL("crypt32.dll").NewProc("CryptMsgClose")
	if closeMessage.Find() == nil {
		_, _, _ = closeMessage.Call(uintptr(message))
	}
}
