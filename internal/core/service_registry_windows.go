//go:build service && windows

package core

import (
	"crypto/rand"
	"encoding/hex"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// servicePipesKeySDDL lets LocalSystem alone write the published names and
// every signed-in account read them.
const servicePipesKeySDDL = "D:P(A;OICI;KA;;;SY)(A;OICI;KR;;;BA)(A;OICI;KR;;;AU)"

type servicePipeNames struct {
	command string
	event   string
}

// newServicePipeNames draws names nobody can create ahead of the service,
// since nobody knows them before it starts.
func newServicePipeNames() (servicePipeNames, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return servicePipeNames{}, err
	}
	suffix := hex.EncodeToString(random)
	return servicePipeNames{
		command: servicePipePrefix + "cmd_" + suffix,
		event:   servicePipePrefix + "events_" + suffix,
	}, nil
}

func publishServicePipes(location registryLocation, names servicePipeNames) error {
	key, _, err := registry.CreateKey(location.root, location.path, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()
	if err := setProtectedDACL(windows.Handle(key), windows.SE_REGISTRY_KEY, servicePipesKeySDDL); err != nil {
		return err
	}
	if err := key.SetStringValue(commandPipeValueName, names.command); err != nil {
		return err
	}
	return key.SetStringValue(eventPipeValueName, names.event)
}

func withdrawServicePipes(location registryLocation) error {
	key, err := registry.OpenKey(location.root, location.path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if err := key.DeleteValue(commandPipeValueName); err != nil {
		return err
	}
	return key.DeleteValue(eventPipeValueName)
}
