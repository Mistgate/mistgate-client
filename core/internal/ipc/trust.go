package ipc

import "strings"

type CallerFacts struct {
	PID                     uint32
	ServicePath             string
	CallerPath              string
	ServiceSigned           bool
	ServiceSignatureValid   bool
	ServiceSignerThumbprint string
	CallerSigned            bool
	CallerSignatureValid    bool
	CallerSignerThumbprint  string
	DevelopmentClientPath   string
}

func IsCallerTrusted(facts CallerFacts) bool {
	if facts.ServiceSigned {
		return facts.ServiceSignatureValid && facts.CallerSigned && facts.CallerSignatureValid &&
			facts.ServiceSignerThumbprint != "" &&
			strings.EqualFold(facts.ServiceSignerThumbprint, facts.CallerSignerThumbprint)
	}

	if facts.DevelopmentClientPath != "" && sameWindowsPath(facts.CallerPath, facts.DevelopmentClientPath) {
		return true
	}
	base := windowsBase(facts.CallerPath)
	return (strings.EqualFold(base, "Mistgate.exe") || strings.EqualFold(base, "mistgate.exe")) &&
		sameWindowsPath(windowsDir(facts.CallerPath), windowsDir(facts.ServicePath))
}

func sameWindowsPath(left, right string) bool {
	return strings.EqualFold(cleanWindowsPath(left), cleanWindowsPath(right))
}

func cleanWindowsPath(path string) string {
	path = strings.ReplaceAll(strings.TrimSpace(path), "/", `\`)
	for strings.Contains(path, `\\`) && !strings.HasPrefix(path, `\\`) {
		path = strings.ReplaceAll(path, `\\`, `\`)
	}
	return strings.TrimRight(path, `\`)
}

func windowsBase(path string) string {
	path = cleanWindowsPath(path)
	if index := strings.LastIndex(path, `\`); index >= 0 {
		return path[index+1:]
	}
	return path
}

func windowsDir(path string) string {
	path = cleanWindowsPath(path)
	if index := strings.LastIndex(path, `\`); index >= 0 {
		return path[:index]
	}
	return ""
}
